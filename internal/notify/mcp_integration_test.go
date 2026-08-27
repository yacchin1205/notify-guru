//go:build integration

package notify

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPEncryptedRoundTrip(t *testing.T) {
	baseURL := os.Getenv("NOTIFY_INTEGRATION_BASE_URL")
	if baseURL == "" {
		t.Fatal("NOTIFY_INTEGRATION_BASE_URL is required")
	}
	api, err := NewAPI(baseURL)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	command := exec.CommandContext(ctx, "go", "run", "../../cmd/notifyg", "--base-url", baseURL, "mcp")
	command.Stderr = os.Stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "notify-guru-integration-test", Version: "0.1.0"}, nil)
	clientSession, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatalf("connect to MCP server: %v", err)
	}
	t.Cleanup(func() {
		if err := clientSession.Close(); err != nil {
			t.Errorf("close MCP client: %v", err)
		}
	})

	created := callTool[pairingToolOutput](t, ctx, clientSession, "session_create", map[string]any{
		"title": "MCP integration",
	})
	assertQRImage(t, created.QRImageURL)
	joined := joinFromPairingURL(t, ctx, api, created.PairingURL)

	waited := callTool[waitDeviceToolOutput](t, ctx, clientSession, "session_wait_for_device", map[string]any{
		"session_id": created.SessionID, "timeout_seconds": 5,
	})
	if waited.DeviceGroupCount != 1 {
		t.Fatalf("device group count = %d, want 1", waited.DeviceGroupCount)
	}

	additionalPairing := callTool[pairingToolOutput](t, ctx, clientSession, "session_pairing_create", map[string]any{
		"session_id": created.SessionID,
	})
	if additionalPairing.PairingURL == created.PairingURL {
		t.Fatal("additional pairing reused the initial one-shot URL")
	}
	assertQRImage(t, additionalPairing.QRImageURL)
	secondGroup := joinFromPairingURL(t, ctx, api, additionalPairing.PairingURL)
	waited = callTool[waitDeviceToolOutput](t, ctx, clientSession, "session_wait_for_device", map[string]any{
		"session_id": created.SessionID, "timeout_seconds": 5,
	})
	if waited.DeviceGroupCount != 2 {
		t.Fatalf("device group count = %d, want 2", waited.DeviceGroupCount)
	}

	callTool[deliveredToolOutput](t, ctx, clientSession, "status", map[string]any{
		"session_id": created.SessionID, "status": "Testing MCP",
	})
	callTool[deliveredToolOutput](t, ctx, clientSession, "notify", map[string]any{
		"session_id": created.SessionID, "message": "Encrypted notification",
	})
	requested := callTool[requestToolOutput](t, ctx, clientSession, "request", map[string]any{
		"session_id": created.SessionID,
		"prompt":     "Continue?",
		"options":    []string{"Go", "NoGo"},
	})
	if len(requested.Choices) != 2 {
		t.Fatalf("choice count = %d, want 2", len(requested.Choices))
	}

	groups := []joinedDeviceGroup{joined, secondGroup}
	var eventsExpiry int64
	for groupIndex, group := range groups {
		events, expiry := fetchAndDecryptEvents(t, ctx, api, created.SessionID, group)
		if groupIndex == 0 {
			eventsExpiry = expiry
		} else if expiry != eventsExpiry {
			t.Fatal("device groups observed different session expiry times")
		}
		if len(events) != 3 {
			t.Fatalf("group %d event count = %d, want 3", groupIndex, len(events))
		}
		wantTypes := []string{"status", "notify", "request"}
		for eventIndex, want := range wantTypes {
			if events[eventIndex].Type != want {
				t.Fatalf("group %d event %d type = %q, want %q", groupIndex, eventIndex, events[eventIndex].Type, want)
			}
			if events[eventIndex].SessionTitle != "MCP integration" {
				t.Fatalf("group %d event %d title = %q", groupIndex, eventIndex, events[eventIndex].SessionTitle)
			}
		}
		if events[2].RequestID != requested.RequestID || events[2].Options[0].ID != requested.Choices[0].ID {
			t.Fatalf("group %d decrypted request does not match the MCP result", groupIndex)
		}
	}

	responseIDs := make([]string, len(groups))
	for index, group := range groups {
		responseIDs[index] = postEncryptedResponse(t, ctx, api, created.SessionID, requested.RequestID, requested.Choices[index].ID, group, eventsExpiry)
	}

	responses := callTool[responsesToolOutput](t, ctx, clientSession, "responses_wait", map[string]any{
		"session_id": created.SessionID, "timeout_seconds": 5,
	})
	if len(responses.Responses) != 2 {
		t.Fatalf("response count = %d, want 2", len(responses.Responses))
	}
	for index, response := range responses.Responses {
		if response.ID != responseIDs[index] || response.RequestID != requested.RequestID || response.OptionID != requested.Choices[index].ID || response.GroupID != groups[index].GroupID {
			t.Fatalf("unexpected response %d: %+v", index, response)
		}
	}

	closed := callTool[closeToolOutput](t, ctx, clientSession, "session_close", map[string]any{
		"session_id": created.SessionID,
	})
	if !closed.Closed {
		t.Fatal("session_close did not report closure")
	}
	err = api.do(ctx, http.MethodGet, fmt.Sprintf("/api/sessions/%s/events?groupId=%s&deviceId=%s&after=0", created.SessionID, joined.GroupID, joined.DeviceID), joined.AccessToken, nil, &struct{}{})
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != http.StatusNotFound {
		t.Fatalf("fetch after close error = %v, want 404 API error", err)
	}
}

func assertQRImage(t *testing.T, imageURL string) {
	t.Helper()
	parsed, err := url.Parse(imageURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		t.Fatalf("QR image URL = %q, want an HTTP IPv4 loopback URL", imageURL)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(imageURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("QR image response status = %d, Content-Type = %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
}

func postEncryptedResponse(
	t *testing.T,
	ctx context.Context,
	api *API,
	sessionID string,
	requestID string,
	optionID string,
	group joinedDeviceGroup,
	expectedExpiry int64,
) string {
	t.Helper()
	responseID, err := randomValue(18)
	if err != nil {
		t.Fatal(err)
	}
	responseBody := decryptedResponse{
		ID:        responseID,
		RequestID: requestID,
		OptionID:  optionID,
		CreatedAt: time.Now().UTC(),
	}
	nonce, ciphertext, err := encryptJSON(
		group.Key,
		responseAAD(sessionID, group.GroupID, responseID, group.Timestamp),
		responseBody,
	)
	if err != nil {
		t.Fatal(err)
	}
	var posted struct {
		ExpiresAt int64 `json:"expiresAt"`
	}
	if err := api.do(ctx, http.MethodPost, "/api/sessions/"+sessionID+"/responses", group.AccessToken, map[string]any{
		"responseId":   responseID,
		"groupId":      group.GroupID,
		"deviceId":     group.DeviceID,
		"keyTimestamp": group.Timestamp,
		"nonce":        nonce,
		"ciphertext":   ciphertext,
	}, &posted); err != nil {
		t.Fatalf("post encrypted response: %v", err)
	}
	if posted.ExpiresAt != expectedExpiry {
		t.Fatal("response unexpectedly changed the session lifetime")
	}
	return responseID
}

type pairingToolOutput struct {
	SessionID  string `json:"session_id"`
	PairingURL string `json:"pairing_url"`
	QRCode     string `json:"qr_code"`
	QRImageURL string `json:"qr_image_url"`
}

type waitDeviceToolOutput struct {
	DeviceGroupCount int `json:"device_group_count"`
}

type deliveredToolOutput struct {
	Delivered bool `json:"delivered"`
}

type requestToolOutput struct {
	RequestID string   `json:"request_id"`
	Choices   []Choice `json:"choices"`
}

type responsesToolOutput struct {
	Responses []Response `json:"responses"`
}

type closeToolOutput struct {
	Closed bool `json:"closed"`
}

type joinedDeviceGroup struct {
	GroupID     string
	DeviceID    string
	AccessToken string
	Timestamp   int64
	Key         []byte
}

func callTool[T any](t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, arguments any) T {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		t.Fatalf("call MCP tool %s: %v", name, err)
	}
	if result.IsError {
		encoded, marshalErr := json.Marshal(result.Content)
		if marshalErr != nil {
			t.Fatalf("marshal MCP tool %s error content: %v", name, marshalErr)
		}
		t.Fatalf("MCP tool %s returned an error: %s", name, encoded)
	}
	encoded, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal MCP tool %s structured result: %v", name, err)
	}
	var output T
	if err := decodeJSON(encoded, &output); err != nil {
		t.Fatalf("decode MCP tool %s structured result: %v", name, err)
	}
	return output
}

func joinFromPairingURL(t *testing.T, ctx context.Context, api *API, rawURL string) joinedDeviceGroup {
	t.Helper()
	pairingURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := url.ParseQuery(pairingURL.Fragment)
	if err != nil {
		t.Fatalf("parse pairing fragment: %v", err)
	}
	if len(parameters) != 6 || parameters.Get("v") != "3" {
		t.Fatalf("unexpected pairing fragment: %q", pairingURL.Fragment)
	}
	sessionID := parameters.Get("s")
	pairingID := parameters.Get("p")
	pairingToken := parameters.Get("t")
	authSecret := parameters.Get("a")
	creatorPublicKey := parameters.Get("k")
	for field, value := range map[string]string{
		"session ID": sessionID, "pairing ID": pairingID, "pairing token": pairingToken,
		"auth secret": authSecret, "creator public key": creatorPublicKey,
	} {
		if value == "" {
			t.Fatalf("pairing URL is missing %s", field)
		}
	}

	groupPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceEncryptionKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := randomValue(18)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, err := randomValue(32)
	if err != nil {
		t.Fatal(err)
	}
	registrationNonce, err := randomValue(32)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := encode(groupPrivateKey.PublicKey().Bytes())
	deviceEncryptionPublicKey := encode(deviceEncryptionKey.PublicKey().Bytes())
	deviceSigningPublicKey := encode(elliptic.Marshal(elliptic.P256(), deviceSigningKey.X, deviceSigningKey.Y))
	var registered struct {
		DeviceID string `json:"deviceId"`
	}
	deviceCreateTranscript := fmt.Sprintf("notify.guru/device-create/v1\n%s\n%s", deviceSigningPublicKey, registrationNonce)
	if err := api.do(ctx, http.MethodPost, "/api/devices", "", map[string]any{
		"signingPublicKey": deviceSigningPublicKey,
		"nonce":            registrationNonce,
		"signature":        signRawP256(t, deviceSigningKey, deviceCreateTranscript),
	}, &registered); err != nil {
		t.Fatalf("register device: %v", err)
	}
	deviceID := registered.DeviceID
	packageNonce, err := randomValue(12)
	if err != nil {
		t.Fatal(err)
	}
	packageCiphertext, err := randomValue(48)
	if err != nil {
		t.Fatal(err)
	}
	keyPackage := map[string]any{
		"deviceId":           deviceID,
		"ephemeralPublicKey": deviceEncryptionPublicKey,
		"nonce":              packageNonce,
		"ciphertext":         packageCiphertext,
	}
	createTranscript := fmt.Sprintf(
		"notify.guru/group-create/v2\n%s\n%s\n%s\n%s",
		groupID, deviceID, tokenHash(accessToken), deviceEncryptionPublicKey,
	)
	deviceSignature := signRawP256(t, deviceSigningKey, createTranscript)
	if err := api.do(ctx, http.MethodPost, "/api/groups", "", map[string]any{
		"groupId":                   groupID,
		"deviceId":                  deviceID,
		"deviceAccessTokenHash":     tokenHash(accessToken),
		"deviceEncryptionPublicKey": deviceEncryptionPublicKey,
		"deviceSignature":           deviceSignature,
	}, &struct {
		Created bool   `json:"created"`
		GroupID string `json:"groupId"`
	}{}); err != nil {
		t.Fatalf("create device group: %v", err)
	}
	var acceptedKey struct {
		Timestamp int64 `json:"timestamp"`
	}
	keyPath := fmt.Sprintf("/api/groups/%s/keys?deviceId=%s", groupID, deviceID)
	keyTranscript := fmt.Sprintf(
		"notify.guru/group-key-register/v1\n%s\n%s\n%s\n1\n1\n%s\n1\n%s\n%s\n%s\n%s",
		groupID, deviceID, publicKey, deviceID,
		deviceID, deviceEncryptionPublicKey, packageNonce, packageCiphertext,
	)
	if err := api.do(ctx, http.MethodPost, keyPath, accessToken, map[string]any{
		"publicKey":      publicKey,
		"recreated":      true,
		"members":        []string{deviceID},
		"packages":       []any{keyPackage},
		"actorSignature": signRawP256(t, deviceSigningKey, keyTranscript),
	}, &acceptedKey); err != nil {
		t.Fatalf("register group key: %v", err)
	}
	secret, err := decode(authSecret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "v3\n%s\n%s\n%s\n%d\n%s", sessionID, pairingID, groupID, acceptedKey.Timestamp, publicKey)
	proof := encode(mac.Sum(nil))

	var result struct {
		Joined    bool  `json:"joined"`
		ExpiresAt int64 `json:"expiresAt"`
	}
	if err := api.do(ctx, http.MethodPost, "/api/sessions/"+sessionID+"/join", "", map[string]any{
		"pairingId":         pairingID,
		"pairingToken":      pairingToken,
		"groupId":           groupID,
		"deviceId":          deviceID,
		"deviceAccessToken": accessToken,
		"keyTimestamp":      acceptedKey.Timestamp,
		"groupPublicKey":    publicKey,
		"proof":             proof,
	}, &result); err != nil {
		t.Fatalf("join device group: %v", err)
	}
	if !result.Joined || result.ExpiresAt <= time.Now().UnixMilli() {
		t.Fatalf("unexpected join result: %+v", result)
	}
	key, err := deriveGroupKey(groupPrivateKey, creatorPublicKey, sessionID, groupID, acceptedKey.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return joinedDeviceGroup{GroupID: groupID, DeviceID: deviceID, AccessToken: accessToken, Timestamp: acceptedKey.Timestamp, Key: key}
}

func signRawP256(t *testing.T, key *ecdsa.PrivateKey, transcript string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(transcript))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return encode(signature)
}

func fetchAndDecryptEvents(t *testing.T, ctx context.Context, api *API, sessionID string, group joinedDeviceGroup) ([]event, int64) {
	t.Helper()
	var result struct {
		Events []struct {
			Sequence     int64  `json:"sequence"`
			EventID      string `json:"eventId"`
			GroupID      string `json:"groupId"`
			KeyTimestamp int64  `json:"keyTimestamp"`
			Nonce        string `json:"nonce"`
			Ciphertext   string `json:"ciphertext"`
			CreatedAt    int64  `json:"createdAt"`
		} `json:"events"`
		ExpiresAt int64 `json:"expiresAt"`
	}
	path := fmt.Sprintf("/api/sessions/%s/events?groupId=%s&deviceId=%s&after=0", sessionID, group.GroupID, group.DeviceID)
	if err := api.do(ctx, http.MethodGet, path, group.AccessToken, nil, &result); err != nil {
		t.Fatalf("fetch encrypted events: %v", err)
	}
	events := make([]event, len(result.Events))
	for index, envelope := range result.Events {
		if envelope.GroupID != group.GroupID {
			t.Fatalf("event group = %q, want %q", envelope.GroupID, group.GroupID)
		}
		if envelope.KeyTimestamp != group.Timestamp {
			t.Fatalf("event key timestamp = %d, want %d", envelope.KeyTimestamp, group.Timestamp)
		}
		if err := decryptJSON(group.Key, eventAAD(sessionID, group.GroupID, envelope.EventID, envelope.KeyTimestamp), envelope.Nonce, envelope.Ciphertext, &events[index]); err != nil {
			t.Fatalf("decrypt event %q: %v", envelope.EventID, err)
		}
	}
	return events, result.ExpiresAt
}
