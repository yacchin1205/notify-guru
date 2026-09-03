package notify

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestResolveColor(t *testing.T) {
	t.Parallel()

	for range 100 {
		color, err := resolveColor("random")
		if err != nil {
			t.Fatal(err)
		}
		if !contains(pastelPalette, color) {
			t.Fatalf("random color %q is not in the pastel palette", color)
		}
	}
	color, err := resolveColor("#A1B2C3")
	if err != nil {
		t.Fatal(err)
	}
	if color != "#a1b2c3" {
		t.Fatalf("normalized color = %q", color)
	}
	if _, err := resolveColor("red"); err == nil {
		t.Fatal("named color was accepted")
	}
}

func TestJoinURLCarriesInitialColorInTheFragment(t *testing.T) {
	t.Parallel()
	api, err := NewAPI("https://notify.guru")
	if err != nil {
		t.Fatal(err)
	}
	value := api.JoinURL("session", Pairing{ID: "pairing", Token: "token", AuthSecret: "secret"}, "public", "#ffd6e0", 4)
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	if fields.Get("c") != "ffd6e0" {
		t.Fatalf("fragment color = %q", fields.Get("c"))
	}
}

func TestEventItemIDUsesTheLogicalItemIdentifier(t *testing.T) {
	t.Parallel()

	notifyID, err := eventItemID(event{ID: "notification", Type: "notify"}, "notify")
	if err != nil {
		t.Fatal(err)
	}
	if notifyID != "notification" {
		t.Fatalf("notify item ID = %q", notifyID)
	}

	requestID, err := eventItemID(event{ID: "envelope-payload", Type: "request", RequestID: "request"}, "request")
	if err != nil {
		t.Fatal(err)
	}
	if requestID != "request" {
		t.Fatalf("request item ID = %q", requestID)
	}

	statusID, err := eventItemID(event{ID: "status", Type: "status"}, "status")
	if err != nil {
		t.Fatal(err)
	}
	if statusID != "" {
		t.Fatalf("status item ID = %q, want none", statusID)
	}

	if _, err := eventItemID(event{ID: "status", Type: "status"}, "notify"); err == nil {
		t.Fatal("status event was accepted as a notification item")
	}
}

func TestEventRetrySchedule(t *testing.T) {
	t.Parallel()

	want := [...]time.Duration{5 * time.Second, 30 * time.Second}
	if eventRetryDelays != want {
		t.Fatalf("event retry delays = %v, want %v", eventRetryDelays, want)
	}
}

func TestRetryEventOperationRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := retryEventOperation(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		if attempts < 3 {
			return &APIError{Status: 503, Code: "unavailable", Message: "temporarily unavailable"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("attempt count = %d, want 3", attempts)
	}
}

func TestRetryEventOperationReturnsTheLastTransientFailure(t *testing.T) {
	t.Parallel()

	attempts := 0
	want := &APIError{Status: 503, Code: "unavailable", Message: "temporarily unavailable"}
	err := retryEventOperation(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if attempts != 3 {
		t.Fatalf("attempt count = %d, want 3", attempts)
	}
}

func TestRetryEventOperationDoesNotRetryPermanentFailure(t *testing.T) {
	t.Parallel()

	attempts := 0
	want := &APIError{Status: 403, Code: "forbidden", Message: "forbidden"}
	err := retryEventOperation(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if attempts != 1 {
		t.Fatalf("attempt count = %d, want 1", attempts)
	}
}

func TestRetryEventOperationStopsWhenTheCallerCancels(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := retryEventOperation(ctx, []time.Duration{time.Hour, time.Hour}, func() error {
		attempts++
		cancel()
		return &transientAPIError{err: context.Canceled}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if attempts != 1 {
		t.Fatalf("attempt count = %d, want 1", attempts)
	}
}

func TestV4ResponsesSkipStaleEpochAndAdvanceCursor(t *testing.T) {
	actorKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	groupSigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	groupPrivateKey, err := ecdh.P256().NewPrivateKey(groupSigningKey.D.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	managerPrivateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const (
		sessionID = "session"
		groupID   = "group"
		timestamp = int64(11)
	)
	actorPublicKey := encode(elliptic.Marshal(elliptic.P256(), actorKey.X, actorKey.Y))
	groupPublicKey := encode(groupPrivateKey.PublicKey().Bytes())
	transition := signedGroupTransition{
		TransitionID: "genesis", PreviousHash: strings.Repeat("0", 64), Timestamp: timestamp,
		ActorDeviceID: "device", PublicKey: groupPublicKey, Recreated: true,
		Members: []transitionMember{{
			DeviceID: "device", SigningPublicKey: actorPublicKey, EncryptionPublicKey: actorPublicKey,
		}},
		PackageDigests: []transitionPackageDigest{{DeviceID: "device", SHA256: strings.Repeat("1", 64)}},
	}
	transcript := groupTransitionTranscript(groupID, transition)
	transition.ActorSignature = signRawP256(t, actorKey, transcript)
	transition.ContinuitySignature = signRawP256(t, groupSigningKey, transcript)
	transition.TransitionHash = groupTransitionHash(groupID, transition)

	currentKey, err := deriveGroupKey(
		managerPrivateKey, groupPublicKey, 4, sessionID, groupID, timestamp,
	)
	if err != nil {
		t.Fatal(err)
	}
	currentResponse := decryptedResponse{
		ID: "current-response", Type: "feedback", Message: "current",
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
	}
	nonce, ciphertext, err := encryptJSON(
		currentKey, responseAAD(4, sessionID, groupID, currentResponse.ID, timestamp), currentResponse,
	)
	if err != nil {
		t.Fatal(err)
	}

	joined := joinedGroup{
		GroupID: groupID, PairingID: "pairing", InitialKeyTimestamp: timestamp,
		InitialPublicKey: groupPublicKey, InitialTransitionHash: transition.TransitionHash,
		Key: &currentGroupKey{
			Timestamp: timestamp, PublicKey: groupPublicKey, Members: []string{"device"},
			TransitionHash: transition.TransitionHash,
		},
		Transitions: []signedGroupTransition{transition},
	}
	stale := responseEnvelope{
		Sequence: 1, ResponseID: "stale-response", GroupID: groupID, KeyTimestamp: timestamp - 1,
		Nonce: "ignored", Ciphertext: "ignored",
	}
	current := responseEnvelope{
		Sequence: 2, ResponseID: currentResponse.ID, GroupID: groupID, KeyTimestamp: timestamp,
		Nonce: nonce, Ciphertext: ciphertext,
	}

	api, err := NewAPI("http://127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	requestedAfter := make([]string, 0, 2)
	api.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var payload any
		switch request.URL.Path {
		case "/api/sessions/session/joins":
			payload = joinsResult{Groups: []joinedGroup{joined}}
		case "/api/sessions/session/responses":
			requestedAfter = append(requestedAfter, request.URL.Query().Get("after"))
			if request.URL.Query().Get("after") == "0" {
				payload = responsesResult{Responses: []responseEnvelope{stale, current}}
			} else {
				payload = responsesResult{}
			}
		default:
			t.Fatalf("unexpected API path %q", request.URL.Path)
		}
		body, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return nil, marshalErr
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body))}, nil
	})

	session := &managedSession{
		id: sessionID, managerToken: "manager", privateKey: managerPrivateKey,
		groups: map[string]*Group{groupID: {
			ID: groupID, PairingID: joined.PairingID, InitialTimestamp: timestamp,
			InitialPublicKey: groupPublicKey, InitialTransitionHash: transition.TransitionHash,
			HeadTransitionHash: transition.TransitionHash, Timestamp: timestamp, PublicKey: groupPublicKey,
			Keys: map[int64][]byte{timestamp: currentKey}, PublicKeys: map[int64]string{timestamp: groupPublicKey},
		}},
		pairings: map[string]Pairing{}, openRequests: map[string]struct{}{}, protocolVersion: 4,
	}
	store := NewStore(api)
	store.sessions[sessionID] = session

	responses, err := store.Responses(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 1 || responses[0].ID != currentResponse.ID || responses[0].Message != currentResponse.Message {
		t.Fatalf("responses = %+v, want only the current-epoch response", responses)
	}
	if session.responseCursor != current.Sequence {
		t.Fatalf("response cursor = %d, want %d", session.responseCursor, current.Sequence)
	}
	responses, err = store.Responses(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(responses) != 0 {
		t.Fatalf("second responses = %+v, want none", responses)
	}
	if len(requestedAfter) != 2 || requestedAfter[0] != "0" || requestedAfter[1] != "2" {
		t.Fatalf("response cursors requested = %v, want [0 2]", requestedAfter)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
