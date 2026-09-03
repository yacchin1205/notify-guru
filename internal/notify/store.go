package notify

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

var colorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

var pastelPalette = []string{
	"#ffd6e0", "#ffe5b4", "#fff3b0", "#d9f2d0",
	"#cdeff2", "#d6e4ff", "#e5d4ff", "#f2d7ee",
}

var eventRetryDelays = [...]time.Duration{5 * time.Second, 30 * time.Second}

const maximumAttachmentCiphertextBytes = 2 * 1024 * 1024
const maximumAttachmentDimension = 2048

type Store struct {
	api      *API
	mu       sync.RWMutex
	sessions map[string]*managedSession
}

type managedSession struct {
	mu              sync.Mutex
	id              string
	title           string
	color           string
	managerToken    string
	privateKey      *ecdh.PrivateKey
	publicKey       string
	pairings        map[string]Pairing
	groups          map[string]*Group
	openRequests    map[string]struct{}
	responseCursor  int64
	protocolVersion int
	tempDir         string
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
	const protocolVersion = 4
	if err := s.api.createSession(ctx, sessionID, tokenHash(managerToken), publicKey, pairing, protocolVersion); err != nil {
		return "", "", err
	}
	session := &managedSession{
		id:              sessionID,
		title:           title,
		color:           color,
		managerToken:    managerToken,
		privateKey:      privateKey,
		publicKey:       publicKey,
		pairings:        map[string]Pairing{pairing.ID: pairing},
		groups:          make(map[string]*Group),
		openRequests:    make(map[string]struct{}),
		protocolVersion: protocolVersion,
	}
	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()
	return sessionID, s.api.JoinURL(sessionID, pairing, publicKey, color, protocolVersion), nil
}

// SessionState describes the session this process manages. PairingURL is empty
// when a device group has already joined and no one needs to scan anything.
type SessionState struct {
	SessionID        string
	Title            string
	Reused           bool
	DeviceGroupCount int
	PairingURL       string
}

// EnsureSession returns the session this process already manages and creates one
// only when there is none. A session identifies the agent, so creating a second
// one for work the person is already following would give them a second card and
// another QR code to scan for no gain. A session the relay no longer knows about
// is dropped and replaced.
func (s *Store) EnsureSession(ctx context.Context, title, color string) (SessionState, error) {
	existing := s.anySessionID()
	if existing != "" {
		state, err := s.reuse(ctx, existing)
		if err == nil {
			return state, nil
		}
		if !isMissingSession(err) {
			return SessionState{}, err
		}
		s.mu.Lock()
		if session, exists := s.sessions[existing]; exists && session.tempDir != "" {
			_ = os.RemoveAll(session.tempDir)
		}
		delete(s.sessions, existing)
		s.mu.Unlock()
	}
	sessionID, pairingURL, err := s.Create(ctx, title, color)
	if err != nil {
		return SessionState{}, err
	}
	return SessionState{SessionID: sessionID, Title: title, PairingURL: pairingURL}, nil
}

func (s *Store) anySessionID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for id := range s.sessions {
		return id
	}
	return ""
}

func (s *Store) reuse(ctx context.Context, sessionID string) (SessionState, error) {
	count, err := s.RefreshGroups(ctx, sessionID)
	if err != nil {
		return SessionState{}, err
	}
	session, err := s.session(sessionID)
	if err != nil {
		return SessionState{}, err
	}
	state := SessionState{SessionID: sessionID, Reused: true, DeviceGroupCount: count}
	session.mu.Lock()
	state.Title = session.title
	unused := unusedPairing(session)
	session.mu.Unlock()
	if count > 0 {
		return state, nil
	}
	if unused.ID != "" {
		state.PairingURL = s.api.JoinURL(sessionID, unused, session.publicKey, session.color, session.protocolVersion)
		return state, nil
	}
	pairingURL, err := s.AddPairing(ctx, sessionID)
	if err != nil {
		return SessionState{}, err
	}
	state.PairingURL = pairingURL
	return state, nil
}

// unusedPairing returns a pairing no device group has consumed, so that reusing a
// session nobody joined yet does not mint another one-shot secret.
func unusedPairing(session *managedSession) Pairing {
	consumed := make(map[string]struct{}, len(session.groups))
	for _, group := range session.groups {
		consumed[group.PairingID] = struct{}{}
	}
	for id, pairing := range session.pairings {
		if _, used := consumed[id]; !used {
			return pairing
		}
	}
	return Pairing{}
}

func isMissingSession(err error) bool {
	var apiError *APIError
	return errors.As(err, &apiError) && apiError.Status == 404
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
	return s.api.JoinURL(session.id, pairing, session.publicKey, session.color, session.protocolVersion), nil
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
		if session.protocolVersion == 4 {
			group, err := s.refreshV4Group(session, joined)
			if err != nil {
				return 0, err
			}
			session.groups[joined.GroupID] = group
			continue
		}
		group, exists := session.groups[joined.GroupID]
		if !exists {
			pairing, known := session.pairings[joined.PairingID]
			if !known {
				return 0, fmt.Errorf("join references unknown pairing %q", joined.PairingID)
			}
			if err := verifyPairingProof(
				pairing.AuthSecret,
				session.protocolVersion,
				session.id,
				joined.PairingID,
				joined.GroupID,
				joined.InitialKeyTimestamp,
				joined.InitialPublicKey,
				"",
				joined.Proof,
			); err != nil {
				return 0, fmt.Errorf("authenticate device group %q: %w", joined.GroupID, err)
			}
			key, err := deriveGroupKey(
				session.privateKey,
				joined.InitialPublicKey,
				session.protocolVersion,
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
				PublicKeys:       map[int64]string{joined.InitialKeyTimestamp: joined.InitialPublicKey},
			}
			session.groups[joined.GroupID] = group
		} else if group.PairingID != joined.PairingID ||
			group.InitialTimestamp != joined.InitialKeyTimestamp ||
			group.InitialPublicKey != joined.InitialPublicKey {
			return 0, fmt.Errorf("server changed authenticated initial state for device group %q", joined.GroupID)
		}
		for _, historical := range joined.Keys {
			if historical.Timestamp < group.InitialTimestamp {
				return 0, fmt.Errorf("device group %q returned a key older than its authenticated initial key", joined.GroupID)
			}
			if knownPublic, known := group.PublicKeys[historical.Timestamp]; known && knownPublic != historical.PublicKey {
				return 0, fmt.Errorf("server changed public key at timestamp %d for device group %q", historical.Timestamp, joined.GroupID)
			}
			if _, known := group.Keys[historical.Timestamp]; !known {
				key, err := deriveGroupKey(
					session.privateKey,
					historical.PublicKey,
					session.protocolVersion,
					session.id,
					joined.GroupID,
					historical.Timestamp,
				)
				if err != nil {
					return 0, err
				}
				group.Keys[historical.Timestamp] = key
			}
			group.PublicKeys[historical.Timestamp] = historical.PublicKey
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
			group.PublicKeys[joined.Key.Timestamp] = joined.Key.PublicKey
			_ = existing
			continue
		}
		key, err := deriveGroupKey(session.privateKey, joined.Key.PublicKey, session.protocolVersion, session.id, joined.GroupID, joined.Key.Timestamp)
		if err != nil {
			return 0, err
		}
		group.Keys[joined.Key.Timestamp] = key
		group.PublicKeys[joined.Key.Timestamp] = joined.Key.PublicKey
		group.Timestamp = joined.Key.Timestamp
		group.PublicKey = joined.Key.PublicKey
	}
	return len(session.groups), nil
}

func (s *Store) refreshV4Group(session *managedSession, joined joinedGroup) (*Group, error) {
	if joined.InitialTransitionHash == "" {
		return nil, fmt.Errorf("device group %q has no authenticated initial transition", joined.GroupID)
	}
	existing, exists := session.groups[joined.GroupID]
	if !exists {
		pairing, known := session.pairings[joined.PairingID]
		if !known {
			return nil, fmt.Errorf("join references unknown pairing %q", joined.PairingID)
		}
		if err := verifyPairingProof(
			pairing.AuthSecret, 4, session.id, joined.PairingID, joined.GroupID,
			joined.InitialKeyTimestamp, joined.InitialPublicKey, joined.InitialTransitionHash, joined.Proof,
		); err != nil {
			return nil, fmt.Errorf("authenticate device group %q: %w", joined.GroupID, err)
		}
	} else if existing.PairingID != joined.PairingID ||
		existing.InitialTimestamp != joined.InitialKeyTimestamp ||
		existing.InitialPublicKey != joined.InitialPublicKey ||
		existing.InitialTransitionHash != joined.InitialTransitionHash {
		return nil, fmt.Errorf("server changed authenticated initial state for device group %q", joined.GroupID)
	}
	trustedHash := joined.InitialTransitionHash
	if exists {
		trustedHash = existing.HeadTransitionHash
	}
	head, err := validateV4Transitions(
		joined.GroupID, joined.Transitions, joined.InitialKeyTimestamp,
		joined.InitialPublicKey, joined.InitialTransitionHash, trustedHash,
	)
	if err != nil {
		return nil, fmt.Errorf("validate device group %q transitions: %w", joined.GroupID, err)
	}
	keys := make(map[int64][]byte)
	publicKeys := make(map[int64]string)
	if exists {
		for timestamp, key := range existing.Keys {
			keys[timestamp] = key
		}
		for timestamp, key := range existing.PublicKeys {
			publicKeys[timestamp] = key
		}
	}
	for _, transition := range joined.Transitions {
		if known, ok := publicKeys[transition.Timestamp]; ok && known != transition.PublicKey {
			return nil, fmt.Errorf("server changed public key at timestamp %d for device group %q", transition.Timestamp, joined.GroupID)
		}
		if _, ok := keys[transition.Timestamp]; !ok {
			key, err := deriveGroupKey(
				session.privateKey, transition.PublicKey, 4, session.id, joined.GroupID, transition.Timestamp,
			)
			if err != nil {
				return nil, err
			}
			keys[transition.Timestamp] = key
		}
		publicKeys[transition.Timestamp] = transition.PublicKey
	}
	group := &Group{
		ID: joined.GroupID, PairingID: joined.PairingID,
		InitialTimestamp: joined.InitialKeyTimestamp, InitialPublicKey: joined.InitialPublicKey,
		InitialTransitionHash: joined.InitialTransitionHash, HeadTransitionHash: head.TransitionHash,
		Keys: keys, PublicKeys: publicKeys,
	}
	if joined.Key == nil {
		return group, nil
	}
	if joined.Key.Timestamp != head.Timestamp || joined.Key.PublicKey != head.PublicKey || joined.Key.TransitionHash != head.TransitionHash {
		return nil, fmt.Errorf("current key does not match authenticated transition head for device group %q", joined.GroupID)
	}
	memberIDs := make([]string, 0, len(head.Members))
	for _, member := range head.Members {
		memberIDs = append(memberIDs, member.DeviceID)
	}
	sort.Strings(memberIDs)
	currentMembers := append([]string(nil), joined.Key.Members...)
	sort.Strings(currentMembers)
	if !slices.Equal(memberIDs, currentMembers) {
		return nil, fmt.Errorf("current members do not match authenticated transition head for device group %q", joined.GroupID)
	}
	group.Timestamp = head.Timestamp
	group.PublicKey = head.PublicKey
	return group, nil
}

func (s *Store) SendNotify(ctx context.Context, sessionID, message string) (string, error) {
	if err := validateText("message", message, 200_000); err != nil {
		return "", err
	}
	itemID, err := randomValue(18)
	if err != nil {
		return "", err
	}
	if err := s.send(ctx, sessionID, event{ID: itemID, Type: "notify", Message: message}, "notify"); err != nil {
		return "", err
	}
	return itemID, nil
}

func (s *Store) SendStatus(ctx context.Context, sessionID, status string) error {
	if err := validateText("status", status, 10_000); err != nil {
		return err
	}
	return s.send(ctx, sessionID, event{Type: "status", Status: status}, "status")
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
		if session.protocolVersion == 4 && (group.Timestamp == 0 || envelope.KeyTimestamp != group.Timestamp) {
			// A response accepted just before rotation can still be queued when the
			// new head is observed. It is no longer safe to decrypt, but must not
			// pin the cursor and block later current-epoch responses forever.
			session.responseCursor = envelope.Sequence
			continue
		}
		key, exists := group.Keys[envelope.KeyTimestamp]
		if !exists {
			return nil, fmt.Errorf("response references unknown key timestamp %d for device group %q", envelope.KeyTimestamp, envelope.GroupID)
		}
		var decrypted decryptedResponse
		if err := decryptJSON(
			key,
			responseAAD(session.protocolVersion, session.id, group.ID, envelope.ResponseID, envelope.KeyTimestamp),
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
			if decrypted.RequestID == "" || decrypted.EventID != "" || decrypted.OptionID == "" || decrypted.Message != "" || decrypted.Attachment != nil || envelope.AttachmentID != "" {
				return nil, fmt.Errorf("response %q has invalid response fields", decrypted.ID)
			}
			if envelope.ItemID != "" && decrypted.RequestID != envelope.ItemID {
				return nil, fmt.Errorf("response %q target does not match its plaintext item ID", decrypted.ID)
			}
		case "dismiss":
			legacyDismiss := envelope.ItemID == "" && decrypted.RequestID != "" && decrypted.EventID == ""
			trackedDismiss := envelope.ItemID != "" && decrypted.EventID != "" && decrypted.RequestID == ""
			if (!legacyDismiss && !trackedDismiss) || decrypted.OptionID != "" || decrypted.Message != "" || decrypted.Attachment != nil || envelope.AttachmentID != "" {
				return nil, fmt.Errorf("response %q has invalid dismiss fields", decrypted.ID)
			}
			if envelope.ItemID != "" && decrypted.EventID != envelope.ItemID {
				return nil, fmt.Errorf("response %q target does not match its plaintext item ID", decrypted.ID)
			}
		case "feedback":
			if decrypted.RequestID != "" || decrypted.EventID != "" || decrypted.OptionID != "" || envelope.ItemID != "" {
				return nil, fmt.Errorf("response %q has invalid feedback fields", decrypted.ID)
			}
			if session.protocolVersion == 3 && (decrypted.Message == "" || decrypted.Attachment != nil || envelope.AttachmentID != "") {
				return nil, fmt.Errorf("response %q has invalid version 3 feedback fields", decrypted.ID)
			}
			if session.protocolVersion == 4 && decrypted.Message == "" && decrypted.Attachment == nil {
				return nil, fmt.Errorf("response %q has neither a message nor an attachment", decrypted.ID)
			}
		default:
			return nil, fmt.Errorf("response %q has unsupported type %q", decrypted.ID, decrypted.Type)
		}
		response := Response{
			ID:        decrypted.ID,
			Type:      decrypted.Type,
			ItemID:    envelope.ItemID,
			RequestID: decrypted.RequestID,
			EventID:   decrypted.EventID,
			OptionID:  decrypted.OptionID,
			Message:   decrypted.Message,
			CreatedAt: decrypted.CreatedAt,
			GroupID:   group.ID,
		}
		if decrypted.Attachment != nil {
			attachment, err := s.receiveAttachment(ctx, session, group, envelope, decrypted.Attachment)
			if err != nil {
				return nil, fmt.Errorf("receive attachment for response %q: %w", decrypted.ID, err)
			}
			response.Attachment = attachment
		} else if envelope.AttachmentID != "" {
			return nil, fmt.Errorf("response %q has an attachment only in its relay envelope", decrypted.ID)
		}
		responses = append(responses, response)
	}
	if len(result.Responses) > 0 {
		session.responseCursor = result.Responses[len(result.Responses)-1].Sequence
	}
	return responses, nil
}

func (s *Store) receiveAttachment(
	ctx context.Context,
	session *managedSession,
	group *Group,
	envelope responseEnvelope,
	manifest *attachmentManifest,
) (*ReceivedAttachment, error) {
	if session.protocolVersion != 4 || envelope.AttachmentID == "" || manifest.ID != envelope.AttachmentID {
		return nil, fmt.Errorf("attachment ID does not match its version 4 response envelope")
	}
	if manifest.Kind != "image" || manifest.MediaType != "image/jpeg" {
		return nil, fmt.Errorf("unsupported attachment kind or media type")
	}
	if manifest.ByteLength <= 0 || manifest.CiphertextLength <= 16 || manifest.CiphertextLength > maximumAttachmentCiphertextBytes {
		return nil, fmt.Errorf("attachment has an invalid length")
	}
	if manifest.CiphertextLength != manifest.ByteLength+16 {
		return nil, fmt.Errorf("attachment ciphertext length does not include exactly one AES-GCM tag")
	}
	if manifest.Width <= 0 || manifest.Height <= 0 || manifest.Width > maximumAttachmentDimension || manifest.Height > maximumAttachmentDimension {
		return nil, fmt.Errorf("attachment has invalid image dimensions")
	}
	if len(manifest.CiphertextSHA256) != 64 {
		return nil, fmt.Errorf("attachment has an invalid ciphertext checksum")
	}
	publicKey, exists := group.PublicKeys[envelope.KeyTimestamp]
	if !exists {
		return nil, fmt.Errorf("attachment references unknown public key timestamp %d", envelope.KeyTimestamp)
	}
	ciphertext, err := s.api.attachment(
		ctx,
		session.id,
		session.managerToken,
		manifest.ID,
		manifest.CiphertextLength,
	)
	if err != nil {
		return nil, err
	}
	if int64(len(ciphertext)) != manifest.CiphertextLength {
		return nil, fmt.Errorf("attachment ciphertext length does not match its manifest")
	}
	digest := sha256.Sum256(ciphertext)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), manifest.CiphertextSHA256) {
		return nil, fmt.Errorf("attachment ciphertext checksum does not match its manifest")
	}
	key, err := deriveAttachmentKey(
		session.privateKey,
		publicKey,
		session.id,
		group.ID,
		envelope.ResponseID,
		manifest.ID,
		envelope.KeyTimestamp,
	)
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptAttachment(
		key,
		attachmentAAD(session.id, group.ID, envelope.ResponseID, manifest.ID, envelope.KeyTimestamp),
		manifest.Nonce,
		ciphertext,
	)
	if err != nil {
		return nil, err
	}
	if int64(len(plaintext)) != manifest.ByteLength {
		return nil, fmt.Errorf("attachment plaintext length does not match its manifest")
	}
	width, height, err := jpegDimensions(plaintext)
	if err != nil {
		return nil, fmt.Errorf("inspect JPEG structure: %w", err)
	}
	if width != manifest.Width || height != manifest.Height {
		return nil, fmt.Errorf("JPEG dimensions do not match the attachment manifest")
	}
	if session.tempDir == "" {
		session.tempDir, err = os.MkdirTemp("", "notifyg-attachments-")
		if err != nil {
			return nil, fmt.Errorf("create attachment temporary directory: %w", err)
		}
		if err := os.Chmod(session.tempDir, 0o700); err != nil {
			return nil, fmt.Errorf("protect attachment temporary directory: %w", err)
		}
	}
	path := filepath.Join(session.tempDir, manifest.ID+".jpg")
	if err := os.WriteFile(path, plaintext, 0o600); err != nil {
		return nil, fmt.Errorf("write attachment temporary file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("protect attachment temporary file: %w", err)
	}
	uri := (&url.URL{Scheme: "file", Path: path}).String()
	return &ReceivedAttachment{
		ID: manifest.ID, Kind: manifest.Kind, MediaType: manifest.MediaType,
		ByteLength: manifest.ByteLength, Width: manifest.Width, Height: manifest.Height,
		Path: path, URI: uri,
	}, nil
}

func jpegDimensions(data []byte) (int, int, error) {
	if len(data) < 4 || data[0] != 0xff || data[1] != 0xd8 {
		return 0, 0, fmt.Errorf("missing JPEG start marker")
	}
	for offset := 2; offset < len(data); {
		for offset < len(data) && data[offset] == 0xff {
			offset++
		}
		if offset >= len(data) {
			break
		}
		marker := data[offset]
		offset++
		if marker == 0x00 || marker == 0xd8 || marker == 0xd9 || marker == 0x01 || marker >= 0xd0 && marker <= 0xd7 {
			continue
		}
		if offset+2 > len(data) {
			return 0, 0, fmt.Errorf("truncated JPEG segment length")
		}
		length := int(data[offset])<<8 | int(data[offset+1])
		if length < 2 || offset+length > len(data) {
			return 0, 0, fmt.Errorf("invalid JPEG segment length")
		}
		if isJPEGStartOfFrame(marker) {
			if length < 8 {
				return 0, 0, fmt.Errorf("truncated JPEG frame header")
			}
			height := int(data[offset+3])<<8 | int(data[offset+4])
			width := int(data[offset+5])<<8 | int(data[offset+6])
			if width == 0 || height == 0 {
				return 0, 0, fmt.Errorf("empty JPEG dimensions")
			}
			return width, height, nil
		}
		if marker == 0xda {
			return 0, 0, fmt.Errorf("JPEG scan begins before a frame header")
		}
		offset += length
	}
	return 0, 0, fmt.Errorf("JPEG frame header was not found")
}

func isJPEGStartOfFrame(marker byte) bool {
	switch marker {
	case 0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf:
		return true
	default:
		return false
	}
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
	if session.tempDir != "" {
		_ = os.RemoveAll(session.tempDir)
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
	if err := retryEventOperation(ctx, eventRetryDelays[:], func() error {
		_, err := s.RefreshGroups(ctx, sessionID)
		return err
	}); err != nil {
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
	if value.ID == "" {
		value.ID, err = randomValue(18)
		if err != nil {
			return err
		}
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
			if refreshErr := retryEventOperation(ctx, eventRetryDelays[:], func() error {
				_, err := s.refreshGroupsLocked(ctx, session)
				return err
			}); refreshErr != nil {
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
	return retryEventOperation(ctx, eventRetryDelays[:], func() error {
		return s.sendToGroupOnce(ctx, session, group, value, notificationKind)
	})
}

func (s *Store) sendToGroupOnce(ctx context.Context, session *managedSession, group *Group, value event, notificationKind string) error {
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
		eventAAD(session.protocolVersion, session.id, group.ID, envelopeID, group.Timestamp),
		value,
	)
	if err != nil {
		return err
	}
	itemID, err := eventItemID(value, notificationKind)
	if err != nil {
		return err
	}
	return s.api.addEvent(
		ctx,
		session.id,
		session.managerToken,
		envelopeID,
		itemID,
		group.ID,
		group.Timestamp,
		nonce,
		ciphertext,
		notificationKind,
	)
}

func retryEventOperation(ctx context.Context, delays []time.Duration, operation func() error) error {
	for attempt := 0; ; attempt++ {
		err := operation()
		if err == nil || attempt == len(delays) || !IsTransientAPIError(ctx, err) {
			return err
		}
		timer := time.NewTimer(delays[attempt])
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func eventItemID(value event, notificationKind string) (string, error) {
	switch notificationKind {
	case "none", "status":
		return "", nil
	case "notify":
		if value.Type != "notify" || value.ID == "" {
			return "", fmt.Errorf("notify event is missing its item ID")
		}
		return value.ID, nil
	case "request":
		if value.Type != "request" || value.RequestID == "" {
			return "", fmt.Errorf("request event is missing its request ID")
		}
		return value.RequestID, nil
	default:
		return "", fmt.Errorf("unsupported notification kind %q", notificationKind)
	}
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
