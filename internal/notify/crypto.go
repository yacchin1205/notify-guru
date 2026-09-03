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

func deriveGroupKey(
	privateKey *ecdh.PrivateKey,
	encodedPublicKey string,
	protocolVersion int,
	sessionID, groupID string,
	timestamp int64,
) ([]byte, error) {
	info := fmt.Sprintf("notify.guru/session/v%d\n%s\n%s\n%d", protocolVersion, sessionID, groupID, timestamp)
	return deriveECDHKey(privateKey, encodedPublicKey, info)
}

func deriveAttachmentKey(
	privateKey *ecdh.PrivateKey,
	encodedPublicKey, sessionID, groupID, responseID, attachmentID string,
	timestamp int64,
) ([]byte, error) {
	info := fmt.Sprintf(
		"notify.guru/attachment/v4\n%s\n%s\n%d\n%s\n%s",
		sessionID,
		groupID,
		timestamp,
		responseID,
		attachmentID,
	)
	return deriveECDHKey(privateKey, encodedPublicKey, info)
}

func deriveECDHKey(privateKey *ecdh.PrivateKey, encodedPublicKey, info string) ([]byte, error) {
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
		return nil, fmt.Errorf("derive group ECDH secret: %w", err)
	}
	key, err := hkdf.Key[hash.Hash](sha256.New, sharedSecret, nil, info, 32)
	if err != nil {
		return nil, fmt.Errorf("derive group session key: %w", err)
	}
	return key, nil
}

func verifyPairingProof(
	authSecret string,
	protocolVersion int,
	sessionID, pairingID, groupID string,
	timestamp int64,
	publicKey, proof string,
) error {
	secret, err := decode(authSecret)
	if err != nil {
		return fmt.Errorf("decode pairing auth secret: %w", err)
	}
	received, err := decode(proof)
	if err != nil {
		return fmt.Errorf("decode pairing proof: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "v%d\n%s\n%s\n%s\n%d\n%s", protocolVersion, sessionID, pairingID, groupID, timestamp, publicKey)
	if !hmac.Equal(received, mac.Sum(nil)) {
		return fmt.Errorf("pairing proof does not authenticate the device group key")
	}
	return nil
}

func decryptAttachment(key []byte, additionalData, encodedNonce string, ciphertext []byte) ([]byte, error) {
	nonce, err := decode(encodedNonce)
	if err != nil {
		return nil, fmt.Errorf("decode attachment nonce: %w", err)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("invalid attachment nonce size: %d", len(nonce))
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(additionalData))
	if err != nil {
		return nil, fmt.Errorf("decrypt attachment: %w", err)
	}
	return plaintext, nil
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
