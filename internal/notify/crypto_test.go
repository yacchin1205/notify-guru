package notify

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestV3GroupKey(t *testing.T) {
	creator, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	group, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	creatorKey, err := deriveGroupKey(creator, encode(group.PublicKey().Bytes()), "session-id", "group-id", 1_789_999_000_001)
	if err != nil {
		t.Fatal(err)
	}
	groupKey, err := deriveGroupKey(group, encode(creator.PublicKey().Bytes()), "session-id", "group-id", 1_789_999_000_001)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(creatorKey, groupKey) {
		t.Fatal("ECDH peers derived different session keys")
	}
	if _, err := deriveGroupKey(group, encode(creator.PublicKey().Bytes()), "session-id", "group-id", 1_789_999_000_002); err != nil {
		t.Fatal(err)
	}
}

func TestECDHEncryptionRoundTrip(t *testing.T) {
	creator, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceGroup, err := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	creatorKey, err := deriveGroupKey(creator, encode(deviceGroup.PublicKey().Bytes()), "session-id", "group-id", 42)
	if err != nil {
		t.Fatal(err)
	}
	deviceGroupKey, err := deriveGroupKey(deviceGroup, encode(creator.PublicKey().Bytes()), "session-id", "group-id", 42)
	if err != nil {
		t.Fatal(err)
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
		t.Fatalf("decrypted response = %+v", got)
	}
	if err := decryptJSON(deviceGroupKey, "different-context", nonce, ciphertext, &got); err == nil {
		t.Fatal("decryptJSON accepted ciphertext under different additional data")
	}
}

func TestV3PairingProofAuthentication(t *testing.T) {
	authSecret, err := randomValue(32)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := decode(authSecret)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	fmt.Fprint(mac, "v3\nsession\npairing\ngroup\n42\npublic-key")
	proof := encode(mac.Sum(nil))
	if err := verifyPairingProofV3(authSecret, "session", "pairing", "group", 42, "public-key", proof); err != nil {
		t.Fatal(err)
	}
	if err := verifyPairingProofV3(authSecret, "session", "pairing", "group", 43, "public-key", proof); err == nil {
		t.Fatal("proof was accepted for another key timestamp")
	}
}
