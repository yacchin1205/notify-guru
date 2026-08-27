package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
)

const keyInfo = "notify.guru/session/v1"

func randomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return encode(value), nil
}

func tokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func deriveKey(privateKey *ecdh.PrivateKey, encodedPublicKey, sessionID string) ([]byte, error) {
	publicBytes, err := decode(encodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode device group public key: %w", err)
	}
	publicKey, err := ecdh.P256().NewPublicKey(publicBytes)
	if err != nil {
		return nil, fmt.Errorf("parse device group public key: %w", err)
	}
	sharedSecret, err := privateKey.ECDH(publicKey)
	if err != nil {
		return nil, fmt.Errorf("derive ECDH secret: %w", err)
	}
	key, err := hkdf.Key[hash.Hash](sha256.New, sharedSecret, []byte(sessionID), keyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	return key, nil
}

func verifyPairingProof(authSecret, sessionID, pairingID, groupID, publicKey, proof string) error {
	secret, err := decode(authSecret)
	if err != nil {
		return fmt.Errorf("decode pairing auth secret: %w", err)
	}
	received, err := decode(proof)
	if err != nil {
		return fmt.Errorf("decode pairing proof: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "v1\n%s\n%s\n%s\n%s", sessionID, pairingID, groupID, publicKey)
	if !hmac.Equal(received, mac.Sum(nil)) {
		return fmt.Errorf("pairing proof does not authenticate the device group key")
	}
	return nil
}

func encryptJSON(key []byte, additionalData string, value any) (nonce, ciphertext string, err error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return "", "", err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return "", "", err
	}
	nonceBytes := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", err
	}
	sealed := aead.Seal(nil, nonceBytes, plaintext, []byte(additionalData))
	return encode(nonceBytes), encode(sealed), nil
}

func decryptJSON(key []byte, additionalData, encodedNonce, encodedCiphertext string, target any) error {
	nonce, err := decode(encodedNonce)
	if err != nil {
		return fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := decode(encodedCiphertext)
	if err != nil {
		return fmt.Errorf("decode ciphertext: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	if len(nonce) != aead.NonceSize() {
		return fmt.Errorf("invalid nonce size: %d", len(nonce))
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(additionalData))
	if err != nil {
		return fmt.Errorf("decrypt payload: %w", err)
	}
	if err := decodeJSON(plaintext, target); err != nil {
		return fmt.Errorf("decode decrypted payload: %w", err)
	}
	return nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func encode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func decode(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}
