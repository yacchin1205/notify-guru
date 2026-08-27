package notify

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestV2GenerationKeyAndSignedTransition(t *testing.T) {
	creator, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	group, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveGenerationKey(group, encode(creator.PublicKey().Bytes()), "session-id", "group-id", 7)
	if err != nil {
		t.Fatal(err)
	}
	if got := encode(key); got != "gXfVAK1yzHMsFX5qQc5sXTEFOXSfDSEVcmNWknyoHgQ" {
		t.Fatalf("v2 generation key = %q", got)
	}

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := encode(elliptic.Marshal(elliptic.P256(), signingKey.X, signingKey.Y))
	transition := GenerationTransition{
		Revision: 2, PreviousGeneration: 1, Generation: 2,
		GenerationPublicKey: publicKey, Action: "add",
		ActorDeviceID: "actor-device", TargetDeviceID: "target-device",
		PackagesHash: strings.Repeat("a", 64),
	}
	transcript := fmt.Sprintf(
		"notify.guru/group-transition/v1\ngroup-id\n2\n1\n2\n%s\nadd\nactor-device\ntarget-device\n%s",
		publicKey, transition.PackagesHash,
	)
	digest := sha256.Sum256([]byte(transcript))
	r, s, err := ecdsa.Sign(rand.Reader, signingKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	transition.GroupSignature = encode(signature)
	if err := verifyGenerationTransition("group-id", transition, publicKey); err != nil {
		t.Fatal(err)
	}
	if err := verifyGenerationTransition("another-group", transition, publicKey); err == nil {
		t.Fatal("transition signature was accepted for another group")
	}
}

func TestECDHEncryptionRoundTrip(t *testing.T) {
	creator, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceGroup, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	creatorKey, err := deriveKey(creator, encode(deviceGroup.PublicKey().Bytes()), "session-id")
	if err != nil {
		t.Fatal(err)
	}
	deviceGroupKey, err := deriveKey(deviceGroup, encode(creator.PublicKey().Bytes()), "session-id")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(creatorKey, deviceGroupKey) {
		t.Fatal("ECDH peers derived different session keys")
	}

	want := decryptedResponse{ID: "response-id", RequestID: "request-id", OptionID: "option-id"}
	nonce, ciphertext, err := encryptJSON(creatorKey, "authenticated-context", want)
	if err != nil {
		t.Fatal(err)
	}
	var got decryptedResponse
	if err := decryptJSON(deviceGroupKey, "authenticated-context", nonce, ciphertext, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != want.ID || got.RequestID != want.RequestID || got.OptionID != want.OptionID {
		t.Fatalf("decrypted response = %+v, want %+v", got, want)
	}
	if err := decryptJSON(deviceGroupKey, "different-context", nonce, ciphertext, &got); err == nil {
		t.Fatal("decryptJSON accepted ciphertext under different additional data")
	}
}

func TestPairingProofAuthentication(t *testing.T) {
	authSecret, err := randomValue(32)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := decode(authSecret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	fmt.Fprint(mac, "v1\nsession\npairing\ngroup\npublic-key")
	proof := encode(mac.Sum(nil))

	if err := verifyPairingProof(authSecret, "session", "pairing", "group", "public-key", proof); err != nil {
		t.Fatal(err)
	}
	if err := verifyPairingProof(authSecret, "session", "pairing", "other-group", "public-key", proof); err == nil {
		t.Fatal("verifyPairingProof accepted a proof for another device group")
	}
}

func TestProtocolVector(t *testing.T) {
	first, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if got := encode(first.PublicKey().Bytes()); got != "BFkat3HrvP1tnLkJTRBlKK3Rpp1EwsH2J_CJ7Fi5xhrfn05qvw0EXAxpOjxorXyXynK-ZN70om_s0mPdmKkngPA" {
		t.Fatalf("first public key = %q", got)
	}
	key, err := deriveKey(first, encode(second.PublicKey().Bytes()), "session-id")
	if err != nil {
		t.Fatal(err)
	}
	if got := encode(key); got != "uaEVrcIWs4cNzciEiU3iqSyYpjF_bNrUm3lu4YXRUZA" {
		t.Fatalf("derived key = %q", got)
	}
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{5}, aead.NonceSize())
	plaintext := []byte(`{"id":"event","type":"notify","sessionTitle":"Build","message":"Done","createdAt":"2026-08-27T00:00:00Z"}`)
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte("notify.guru/v1/event/session-id/first/event-id"))
	if got := encode(ciphertext); got != "OzZ_nSEMbRHBMJSlsDuAdnPzTFnot1-_kPLLyMolGCimmFQOP7y_PuDnxwK9X8DJj7pXPloDhoOVERbJEDqzoHkfmTMz6bX-_iXgBlJunarXseLIdfEUXc-DxfapQgI_Io4_SYhuu7RqGovKQ8uPpFn6XtONGgxPCQ" {
		t.Fatalf("event ciphertext = %q", got)
	}
}

func TestDecodeJSONRejectsProtocolDrift(t *testing.T) {
	tests := []string{
		`{"id":"response","requestId":"request","optionId":"option","createdAt":"2026-08-27T00:00:00Z","unknown":true}`,
		`{"id":"response","requestId":"request","optionId":"option","createdAt":"2026-08-27T00:00:00Z"} {}`,
	}
	for _, input := range tests {
		var response decryptedResponse
		if err := decodeJSON([]byte(input), &response); err == nil {
			t.Fatalf("decodeJSON accepted invalid protocol input: %s", input)
		}
	}
}

func TestNewAPIRejectsUnsafeOrAmbiguousBaseURLs(t *testing.T) {
	for _, rawURL := range []string{
		"http://notify.guru",
		"https://notify.guru/path",
		"https://notify.guru?query=true",
		"https://notify.guru/#fragment",
	} {
		if _, err := NewAPI(rawURL); err == nil {
			t.Fatalf("NewAPI accepted %q", rawURL)
		}
	}
	for _, rawURL := range []string{"https://notify.guru", "http://localhost:8787"} {
		if _, err := NewAPI(rawURL); err != nil {
			t.Fatalf("NewAPI rejected %q: %v", rawURL, err)
		}
	}
}
