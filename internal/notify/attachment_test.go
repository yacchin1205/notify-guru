package notify

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResponsesRejectUnsafeAttachmentIDs(t *testing.T) {
	actor, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	groupPrivate, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	creator, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID, groupID, responseID = "session", "group", "response"
	const timestamp = int64(42)
	groupPublic := encode(groupPrivate.PublicKey().Bytes())
	actorPublic := encode(elliptic.Marshal(elliptic.P256(), actor.X, actor.Y))
	// This head is already authenticated by the pairing exchange.
	head := signedGroupTransition{
		TransitionID: "anchor", PreviousHash: strings.Repeat("a", 64), Timestamp: timestamp,
		ActorDeviceID: "device", PublicKey: groupPublic, Recreated: true,
		Members:        []transitionMember{{DeviceID: "device", SigningPublicKey: actorPublic, EncryptionPublicKey: actorPublic}},
		PackageDigests: []transitionPackageDigest{{DeviceID: "device", SHA256: strings.Repeat("b", 64)}},
	}
	head.TransitionHash = groupTransitionHash(groupID, head)
	responseKey, err := deriveGroupKey(groupPrivate, encode(creator.PublicKey().Bytes()), 4, sessionID, groupID, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	var photo bytes.Buffer
	// A one-pixel JPEG frame, matching the receiver's supported structure.
	photo.Write([]byte{0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 0, 1, 0, 1, 1, 1, 0x11, 0, 0xff, 0xd9})
	for _, tc := range []struct {
		name, id string
		valid    bool
	}{
		{"valid", "0123456789abCD_-", true},
		{"parent", "../outside", false},
		{"windows-parent", `..\outside`, false},
		{"nested", "directory/attachment", false},
		{"absolute", "/outside/attachment", false},
		{"short", "short", false},
		{"long", strings.Repeat("a", 65), false},
		{"maximum", strings.Repeat("a", 64), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tempDir := filepath.Join(root, "attachments")
			if err := os.Mkdir(tempDir, 0o700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(root, "outside.jpg")
			if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
				t.Fatal(err)
			}
			key, err := deriveAttachmentKey(groupPrivate, encode(creator.PublicKey().Bytes()), sessionID, groupID, responseID, tc.id, timestamp)
			if err != nil {
				t.Fatal(err)
			}
			aead, err := newAEAD(key)
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, aead.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			ciphertext := aead.Seal(nil, nonce, photo.Bytes(), []byte(attachmentAAD(sessionID, groupID, responseID, tc.id, timestamp)))
			digest := sha256.Sum256(ciphertext)
			manifest := &attachmentManifest{
				ID: tc.id, Kind: "image", MediaType: "image/jpeg", Width: 1, Height: 1,
				ByteLength: int64(photo.Len()), CiphertextLength: int64(len(ciphertext)),
				Nonce: encode(nonce), CiphertextSHA256: hex.EncodeToString(digest[:]),
			}
			responseNonce, responseCiphertext, err := encryptJSON(responseKey, responseAAD(4, sessionID, groupID, responseID, timestamp), decryptedResponse{
				ID: responseID, Type: "feedback", CreatedAt: time.Now().UTC(), Attachment: manifest,
			})
			if err != nil {
				t.Fatal(err)
			}
			api, err := NewAPI("http://127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			downloads := 0
			api.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				var payload any
				switch request.URL.Path {
				case "/api/sessions/session":
					payload = joinsResult{Groups: []joinedGroup{{
						GroupID: groupID, PairingID: "pairing", InitialKeyTimestamp: timestamp, InitialPublicKey: groupPublic,
						InitialTransitionHash: head.TransitionHash, Transitions: []signedGroupTransition{head},
						Key: &currentGroupKey{Timestamp: timestamp, PublicKey: groupPublic, TransitionHash: head.TransitionHash, Members: []string{"device"}},
					}}}
				case "/api/sessions/session/responses":
					payload = responsesResult{Responses: []responseEnvelope{{
						Sequence: 1, ResponseID: responseID, GroupID: groupID, KeyTimestamp: timestamp,
						AttachmentID: tc.id, Nonce: responseNonce, Ciphertext: responseCiphertext,
					}}}
				default:
					if !strings.HasPrefix(request.URL.Path, "/api/sessions/session/attachments/") {
						t.Fatalf("unexpected request: %s", request.URL.Path)
					}
					downloads++
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/octet-stream"}}, Body: io.NopCloser(bytes.NewReader(ciphertext))}, nil
				}
				body, err := json.Marshal(payload)
				if err != nil {
					return nil, err
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})
			store := NewStore(api)
			store.sessions[sessionID] = &managedSession{
				id: sessionID, privateKey: creator, protocolVersion: 4, tempDir: tempDir,
				groups: map[string]*Group{groupID: {
					ID: groupID, PairingID: "pairing", InitialTimestamp: timestamp, InitialPublicKey: groupPublic,
					InitialTransitionHash: head.TransitionHash, HeadTransitionHash: head.TransitionHash,
				}},
			}
			responses, receiveErr := store.Responses(context.Background(), sessionID)
			data, err := os.ReadFile(outside)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "untouched" {
				t.Fatal("receiving an attachment overwrote a file outside its directory")
			}
			entries, err := os.ReadDir(tempDir)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.valid {
				if receiveErr == nil || !strings.Contains(receiveErr.Error(), "invalid attachment ID") {
					t.Fatalf("error = %v, want invalid attachment ID", receiveErr)
				}
				if len(responses) != 0 || len(entries) != 0 || downloads != 0 {
					t.Fatalf("rejected attachment produced output: responses=%d files=%d downloads=%d", len(responses), len(entries), downloads)
				}
				return
			}
			if receiveErr != nil {
				t.Fatal(receiveErr)
			}
			if len(responses) != 1 || responses[0].Attachment == nil {
				t.Fatalf("missing attachment: %+v", responses)
			}
			attachment := responses[0].Attachment
			if attachment.Path != filepath.Join(tempDir, tc.id+".jpg") || len(entries) != 1 {
				t.Fatalf("unexpected saved attachment: %+v", attachment)
			}
			data, err = os.ReadFile(attachment.Path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, photo.Bytes()) {
				t.Fatal("saved photo does not match the encrypted attachment")
			}
			if attachment.URI != (&url.URL{Scheme: "file", Path: attachment.Path}).String() {
				t.Fatalf("incorrect resource URI: %s", attachment.URI)
			}
		})
	}
}
