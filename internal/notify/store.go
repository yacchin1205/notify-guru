package notify

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"time"
)

var colorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

var pastelPalette = []string{
	"#ffd6e0", "#ffe5b4", "#fff3b0", "#d9f2d0",
	"#cdeff2", "#d6e4ff", "#e5d4ff", "#f2d7ee",
}

type Store struct {
	api      *API
	mu       sync.RWMutex
	sessions map[string]*managedSession
}

type managedSession struct {
	mu             sync.Mutex
	id             string
	title          string
	color          string
	managerToken   string
	privateKey     *ecdh.PrivateKey
	publicKey      string
	pairings       map[string]Pairing
	groups         map[string]*Group
	openRequests   map[string]struct{}
	responseCursor int64
}

func NewStore(api *API) *Store {
	return &Store{api: api, sessions: make(map[string]*managedSession)}
}

func (s *Store) Create(ctx context.Context, title, color string) (sessionID, pairingURL string, err error) {
	if err := validateText("title", title, 200); err != nil {
		return "", "", err
	}
	color, err = resolveColor(color)
	if err != nil {
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
		color:        color,
		managerToken: managerToken,
		privateKey:   privateKey,
		publicKey:    publicKey,
		pairings:     map[string]Pairing{pairing.ID: pairing},
		groups:       make(map[string]*Group),
		openRequests: make(map[string]struct{}),
	}
	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()
	return sessionID, s.api.JoinURL(sessionID, pairing, publicKey, color), nil
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
	return s.api.JoinURL(session.id, pairing, session.publicKey, session.color), nil
}

func (s *Store) RefreshGroups(ctx context.Context, sessionID string) (int, error) {
	session, err := s.session(sessionID)
	if err != nil {
		return 0, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return s.refreshGroupsLocked(ctx, session)
}

func (s *Store) refreshGroupsLocked(ctx context.Context, session *managedSession) (int, error) {
	result, err := s.api.joins(ctx, session.id, session.managerToken)
	if err != nil {
		return 0, err
	}
	for _, joined := range result.Groups {
		group, exists := session.groups[joined.GroupID]
		if !exists {
			pairing, known := session.pairings[joined.PairingID]
			if !known {
				return 0, fmt.Errorf("join references unknown pairing %q", joined.PairingID)
			}
			if err := verifyPairingProofV3(
				pairing.AuthSecret,
				session.id,
				joined.PairingID,
				joined.GroupID,
				joined.InitialKeyTimestamp,
				joined.InitialPublicKey,
				joined.Proof,
			); err != nil {
				return 0, fmt.Errorf("authenticate device group %q: %w", joined.GroupID, err)
			}
			key, err := deriveGroupKey(
				session.privateKey,
				joined.InitialPublicKey,
				session.id,
				joined.GroupID,
				joined.InitialKeyTimestamp,
			)
			if err != nil {
				return 0, err
			}
			group = &Group{
				ID:               joined.GroupID,
				PairingID:        joined.PairingID,
				InitialTimestamp: joined.InitialKeyTimestamp,
				InitialPublicKey: joined.InitialPublicKey,
				Timestamp:        joined.InitialKeyTimestamp,
				PublicKey:        joined.InitialPublicKey,
				Keys:             map[int64][]byte{joined.InitialKeyTimestamp: key},
			}
			session.groups[joined.GroupID] = group
		} else if group.PairingID != joined.PairingID ||
			group.InitialTimestamp != joined.InitialKeyTimestamp ||
			group.InitialPublicKey != joined.InitialPublicKey {
			return 0, fmt.Errorf("server changed authenticated initial state for device group %q", joined.GroupID)
		}
		if joined.Key == nil {
			group.Timestamp = 0
			group.PublicKey = ""
			continue
		}
		if existing, known := group.Keys[joined.Key.Timestamp]; known {
			if group.Timestamp == joined.Key.Timestamp && group.PublicKey != joined.Key.PublicKey {
				return 0, fmt.Errorf("server changed public key at timestamp %d for device group %q", joined.Key.Timestamp, joined.GroupID)
			}
			group.Timestamp = joined.Key.Timestamp
			group.PublicKey = joined.Key.PublicKey
			_ = existing
			continue
		}
		key, err := deriveGroupKey(session.privateKey, joined.Key.PublicKey, session.id, joined.GroupID, joined.Key.Timestamp)
		if err != nil {
			return 0, err
		}
		group.Keys[joined.Key.Timestamp] = key
		group.Timestamp = joined.Key.Timestamp
		group.PublicKey = joined.Key.PublicKey
	}
	return len(session.groups), nil
}

func (s *Store) SendNotify(ctx context.Context, sessionID, message string) error {
	if err := validateText("message", message, 200_000); err != nil {
		return err
	}
	return s.send(ctx, sessionID, event{Type: "notify", Message: message}, "notify")
}

func (s *Store) SendStatus(ctx context.Context, sessionID, status string) error {
	if err := validateText("status", status, 10_000); err != nil {
		return err
	}
	return s.send(ctx, sessionID, event{Type: "status", Status: status}, "none")
}

func (s *Store) SetColor(ctx context.Context, sessionID, color string) error {
	color, err := resolveColor(color)
	if err != nil {
		return err
	}
	return s.send(ctx, sessionID, event{Type: "color", Color: color}, "none")
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
	if err := s.send(ctx, sessionID, event{Type: "request", RequestID: requestID, Prompt: prompt, Options: choices}, "request"); err != nil {
		return "", nil, err
	}
	session, err := s.session(sessionID)
	if err != nil {
		return "", nil, err
	}
	session.mu.Lock()
	session.openRequests[requestID] = struct{}{}
	session.mu.Unlock()
	return requestID, choices, nil
}

func (s *Store) CloseRequest(ctx context.Context, sessionID, requestID string) error {
	if err := validateText("request ID", requestID, 64); err != nil {
		return err
	}
	session, err := s.session(sessionID)
	if err != nil {
		return err
	}
	session.mu.Lock()
	_, open := session.openRequests[requestID]
	session.mu.Unlock()
	if !open {
		return fmt.Errorf("request %q is not open", requestID)
	}
	if err := s.send(ctx, sessionID, event{Type: "close_request", RequestID: requestID}, "none"); err != nil {
		return err
	}
	session.mu.Lock()
	delete(session.openRequests, requestID)
	session.mu.Unlock()
	return nil
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
		key, exists := group.Keys[envelope.KeyTimestamp]
		if !exists {
			return nil, fmt.Errorf("response references unknown key timestamp %d for device group %q", envelope.KeyTimestamp, envelope.GroupID)
		}
		var decrypted decryptedResponse
		if err := decryptJSON(
			key,
			responseAAD(session.id, group.ID, envelope.ResponseID, envelope.KeyTimestamp),
			envelope.Nonce,
			envelope.Ciphertext,
			&decrypted,
		); err != nil {
			return nil, fmt.Errorf("decrypt response %q: %w", envelope.ResponseID, err)
		}
		if decrypted.ID != envelope.ResponseID {
			return nil, fmt.Errorf("response ID does not match its encrypted envelope")
		}
		if decrypted.ID == "" || decrypted.CreatedAt.IsZero() {
			return nil, fmt.Errorf("response %q is missing a required field", decrypted.ID)
		}
		switch decrypted.Type {
		case "response":
			if decrypted.RequestID == "" || decrypted.OptionID == "" || decrypted.Message != "" {
				return nil, fmt.Errorf("response %q has invalid response fields", decrypted.ID)
			}
		case "feedback":
			if decrypted.Message == "" || decrypted.RequestID != "" || decrypted.OptionID != "" {
				return nil, fmt.Errorf("response %q has invalid feedback fields", decrypted.ID)
			}
		default:
			return nil, fmt.Errorf("response %q has unsupported type %q", decrypted.ID, decrypted.Type)
		}
		response := Response{
			ID:        decrypted.ID,
			Type:      decrypted.Type,
			RequestID: decrypted.RequestID,
			OptionID:  decrypted.OptionID,
			Message:   decrypted.Message,
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

func (s *Store) send(ctx context.Context, sessionID string, value event, notificationKind string) error {
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
	if value.Type == "color" {
		if value.Color == "" {
			return fmt.Errorf("color event is missing its color")
		}
	} else {
		if value.Color != "" {
			return fmt.Errorf("non-color event contains an explicit color")
		}
		value.Color = session.color
	}
	value.CreatedAt = time.Now().UTC()
	for _, group := range session.groups {
		if err := s.sendToGroup(ctx, session, group, value, notificationKind); err != nil {
			var apiError *APIError
			if !errors.As(err, &apiError) || apiError.Code != "group_key_unavailable" {
				return err
			}
			if _, refreshErr := s.refreshGroupsLocked(ctx, session); refreshErr != nil {
				return fmt.Errorf("refresh unavailable device group key: %w", refreshErr)
			}
			if retryErr := s.sendToGroup(ctx, session, group, value, notificationKind); retryErr != nil {
				return fmt.Errorf("send after refreshing device group key: %w", retryErr)
			}
		}
	}
	if value.Type == "color" {
		session.color = value.Color
	}
	return nil
}

func (s *Store) sendToGroup(ctx context.Context, session *managedSession, group *Group, value event, notificationKind string) error {
	if group.Timestamp == 0 {
		return fmt.Errorf("device group %q has no key available for new events", group.ID)
	}
	envelopeID, err := randomValue(18)
	if err != nil {
		return err
	}
	key, exists := group.Keys[group.Timestamp]
	if !exists {
		return fmt.Errorf("missing current key for device group %q timestamp %d", group.ID, group.Timestamp)
	}
	nonce, ciphertext, err := encryptJSON(
		key,
		eventAAD(session.id, group.ID, envelopeID, group.Timestamp),
		value,
	)
	if err != nil {
		return err
	}
	return s.api.addEvent(
		ctx,
		session.id,
		session.managerToken,
		envelopeID,
		group.ID,
		group.Timestamp,
		nonce,
		ciphertext,
		notificationKind,
	)
}

func resolveColor(value string) (string, error) {
	if value == "" || value == "random" {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(pastelPalette))))
		if err != nil {
			return "", fmt.Errorf("select random pastel color: %w", err)
		}
		return pastelPalette[index.Int64()], nil
	}
	if !colorPattern.MatchString(value) {
		return "", fmt.Errorf("color must be random or #rrggbb")
	}
	return strings.ToLower(value), nil
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
