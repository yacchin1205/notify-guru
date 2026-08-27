package notify

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

type Store struct {
	api      *API
	mu       sync.RWMutex
	sessions map[string]*managedSession
}

type managedSession struct {
	mu             sync.Mutex
	id             string
	title          string
	managerToken   string
	privateKey     *ecdh.PrivateKey
	publicKey      string
	pairings       map[string]Pairing
	groups         map[string]Group
	joinCursor     int64
	responseCursor int64
}

func NewStore(api *API) *Store {
	return &Store{api: api, sessions: make(map[string]*managedSession)}
}

func (s *Store) Create(ctx context.Context, title string) (sessionID, pairingURL string, err error) {
	if err := validateText("title", title, 200); err != nil {
		return "", "", err
	}
	sessionID, err = randomValue(18)
	if err != nil {
		return "", "", err
	}
	managerToken, err := randomValue(32)
	if err != nil {
		return "", "", err
	}
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	pairing, err := newPairing()
	if err != nil {
		return "", "", err
	}
	publicKey := encode(privateKey.PublicKey().Bytes())
	if err := s.api.createSession(ctx, sessionID, tokenHash(managerToken), publicKey, pairing); err != nil {
		return "", "", err
	}
	session := &managedSession{
		id:           sessionID,
		title:        title,
		managerToken: managerToken,
		privateKey:   privateKey,
		publicKey:    publicKey,
		pairings:     map[string]Pairing{pairing.ID: pairing},
		groups:       make(map[string]Group),
	}
	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()
	return sessionID, s.api.JoinURL(sessionID, pairing, publicKey), nil
}

func (s *Store) AddPairing(ctx context.Context, sessionID string) (string, error) {
	session, err := s.session(sessionID)
	if err != nil {
		return "", err
	}
	pairing, err := newPairing()
	if err != nil {
		return "", err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := s.api.addPairing(ctx, session.id, session.managerToken, pairing); err != nil {
		return "", err
	}
	session.pairings[pairing.ID] = pairing
	return s.api.JoinURL(session.id, pairing, session.publicKey), nil
}

func (s *Store) RefreshGroups(ctx context.Context, sessionID string) (int, error) {
	session, err := s.session(sessionID)
	if err != nil {
		return 0, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	result, err := s.api.joins(ctx, session.id, session.managerToken, session.joinCursor)
	if err != nil {
		return 0, err
	}
	for _, joined := range result.Groups {
		pairing, exists := session.pairings[joined.PairingID]
		if !exists {
			return 0, fmt.Errorf("join references unknown pairing %q", joined.PairingID)
		}
		if err := verifyPairingProof(pairing.AuthSecret, session.id, joined.PairingID, joined.GroupID, joined.PublicKey, joined.Proof); err != nil {
			return 0, fmt.Errorf("authenticate device group %q: %w", joined.GroupID, err)
		}
		key, err := deriveKey(session.privateKey, joined.PublicKey, session.id)
		if err != nil {
			return 0, err
		}
		session.groups[joined.GroupID] = Group{ID: joined.GroupID, Key: key}
		session.joinCursor = joined.Sequence
	}
	return len(session.groups), nil
}

func (s *Store) SendNotify(ctx context.Context, sessionID, message string) error {
	if err := validateText("message", message, 200_000); err != nil {
		return err
	}
	return s.send(ctx, sessionID, event{Type: "notify", Message: message})
}

func (s *Store) SendStatus(ctx context.Context, sessionID, status string) error {
	if err := validateText("status", status, 10_000); err != nil {
		return err
	}
	return s.send(ctx, sessionID, event{Type: "status", Status: status})
}

func (s *Store) SendRequest(ctx context.Context, sessionID, prompt string, optionLabels []string) (string, []Choice, error) {
	if err := validateText("prompt", prompt, 20_000); err != nil {
		return "", nil, err
	}
	if len(optionLabels) < 2 || len(optionLabels) > 20 {
		return "", nil, fmt.Errorf("request must contain between 2 and 20 options")
	}
	choices := make([]Choice, len(optionLabels))
	for index, label := range optionLabels {
		if err := validateText(fmt.Sprintf("option %d", index+1), label, 500); err != nil {
			return "", nil, err
		}
		id, err := randomValue(18)
		if err != nil {
			return "", nil, err
		}
		choices[index] = Choice{ID: id, Label: label}
	}
	requestID, err := randomValue(18)
	if err != nil {
		return "", nil, err
	}
	if err := s.send(ctx, sessionID, event{Type: "request", RequestID: requestID, Prompt: prompt, Options: choices}); err != nil {
		return "", nil, err
	}
	return requestID, choices, nil
}

func (s *Store) Responses(ctx context.Context, sessionID string) ([]Response, error) {
	if _, err := s.RefreshGroups(ctx, sessionID); err != nil {
		return nil, err
	}
	session, err := s.session(sessionID)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	result, err := s.api.responses(ctx, session.id, session.managerToken, session.responseCursor)
	if err != nil {
		return nil, err
	}
	responses := make([]Response, 0, len(result.Responses))
	for _, envelope := range result.Responses {
		group, exists := session.groups[envelope.GroupID]
		if !exists {
			return nil, fmt.Errorf("response references unknown device group %q", envelope.GroupID)
		}
		var decrypted decryptedResponse
		if err := decryptJSON(group.Key, responseAAD(session.id, group.ID, envelope.ResponseID), envelope.Nonce, envelope.Ciphertext, &decrypted); err != nil {
			return nil, fmt.Errorf("decrypt response %q: %w", envelope.ResponseID, err)
		}
		if decrypted.ID != envelope.ResponseID {
			return nil, fmt.Errorf("response ID does not match its encrypted envelope")
		}
		if decrypted.RequestID == "" || decrypted.OptionID == "" || decrypted.CreatedAt.IsZero() {
			return nil, fmt.Errorf("response %q is missing a required field", decrypted.ID)
		}
		response := Response{
			ID:        decrypted.ID,
			RequestID: decrypted.RequestID,
			OptionID:  decrypted.OptionID,
			CreatedAt: decrypted.CreatedAt,
			GroupID:   group.ID,
		}
		responses = append(responses, response)
		session.responseCursor = envelope.Sequence
	}
	return responses, nil
}

func (s *Store) WaitForGroups(ctx context.Context, sessionID string, timeout time.Duration) (int, error) {
	if timeout <= 0 || timeout > 10*time.Minute {
		return 0, fmt.Errorf("timeout must be between 1ns and 10m")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		count, err := s.RefreshGroups(ctx, sessionID)
		if err != nil {
			return 0, err
		}
		if count > 0 {
			return count, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-deadline.C:
			return 0, context.DeadlineExceeded
		case <-ticker.C:
		}
	}
}

func (s *Store) WaitResponses(ctx context.Context, sessionID string, timeout time.Duration) ([]Response, error) {
	if timeout <= 0 || timeout > 10*time.Minute {
		return nil, fmt.Errorf("timeout must be between 1ns and 10m")
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		responses, err := s.Responses(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		if len(responses) > 0 {
			return responses, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return []Response{}, nil
		case <-ticker.C:
		}
	}
}

func (s *Store) Close(ctx context.Context, sessionID string) error {
	session, err := s.session(sessionID)
	if err != nil {
		return err
	}
	session.mu.Lock()
	err = s.api.closeSession(ctx, session.id, session.managerToken)
	session.mu.Unlock()
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	return nil
}

func (s *Store) send(ctx context.Context, sessionID string, value event) error {
	if _, err := s.RefreshGroups(ctx, sessionID); err != nil {
		return err
	}
	session, err := s.session(sessionID)
	if err != nil {
		return err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.groups) == 0 {
		return fmt.Errorf("session has no authenticated device groups")
	}
	value.ID, err = randomValue(18)
	if err != nil {
		return err
	}
	value.SessionTitle = session.title
	value.CreatedAt = time.Now().UTC()
	for _, group := range session.groups {
		envelopeID, err := randomValue(18)
		if err != nil {
			return err
		}
		nonce, ciphertext, err := encryptJSON(group.Key, eventAAD(session.id, group.ID, envelopeID), value)
		if err != nil {
			return err
		}
		if err := s.api.addEvent(ctx, session.id, session.managerToken, envelopeID, group.ID, nonce, ciphertext); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) session(sessionID string) (*managedSession, error) {
	s.mu.RLock()
	session, exists := s.sessions[sessionID]
	s.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("unknown local session %q", sessionID)
	}
	return session, nil
}

func newPairing() (Pairing, error) {
	id, err := randomValue(18)
	if err != nil {
		return Pairing{}, err
	}
	token, err := randomValue(32)
	if err != nil {
		return Pairing{}, err
	}
	authSecret, err := randomValue(32)
	if err != nil {
		return Pairing{}, err
	}
	return Pairing{ID: id, Token: token, AuthSecret: authSecret}, nil
}
