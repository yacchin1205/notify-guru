package notify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"sort"
	"strings"
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
	publicKey, transitionHash, proof string,
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
	if protocolVersion == 4 {
		fmt.Fprintf(mac, "\n%s", transitionHash)
	}
	if !hmac.Equal(received, mac.Sum(nil)) {
		return fmt.Errorf("pairing proof does not authenticate the device group key")
	}
	return nil
}

func groupTransitionTranscript(groupID string, transition signedGroupTransition) string {
	members := append([]transitionMember(nil), transition.Members...)
	digests := append([]transitionPackageDigest(nil), transition.PackageDigests...)
	sort.Slice(members, func(i, j int) bool { return members[i].DeviceID < members[j].DeviceID })
	sort.Slice(digests, func(i, j int) bool { return digests[i].DeviceID < digests[j].DeviceID })
	lines := []string{
		"notify.guru/group-transition/v1", groupID, transition.TransitionID, transition.PreviousHash,
		fmt.Sprint(transition.Timestamp), transition.ActorDeviceID, transition.PublicKey,
		map[bool]string{true: "1", false: "0"}[transition.Recreated], fmt.Sprint(len(members)),
	}
	for _, member := range members {
		lines = append(lines, member.DeviceID, member.SigningPublicKey, member.EncryptionPublicKey)
	}
	lines = append(lines, fmt.Sprint(len(digests)))
	for _, digest := range digests {
		lines = append(lines, digest.DeviceID, digest.SHA256)
	}
	return strings.Join(lines, "\n")
}

func groupTransitionHash(groupID string, transition signedGroupTransition) string {
	value := strings.Join([]string{
		"notify.guru/group-transition-hash/v2", groupTransitionTranscript(groupID, transition),
	}, "\n")
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func verifyP256Signature(publicKey, signature, transcript string) error {
	publicBytes, err := decode(publicKey)
	if err != nil {
		return fmt.Errorf("decode P-256 public key: %w", err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	if x == nil {
		return fmt.Errorf("parse P-256 public key")
	}
	signatureBytes, err := decode(signature)
	if err != nil {
		return fmt.Errorf("decode P-256 signature: %w", err)
	}
	if len(signatureBytes) != 64 {
		return fmt.Errorf("P-256 signature must contain 64 bytes")
	}
	digest := sha256.Sum256([]byte(transcript))
	if !ecdsa.Verify(
		&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:],
		new(big.Int).SetBytes(signatureBytes[:32]), new(big.Int).SetBytes(signatureBytes[32:]),
	) {
		return fmt.Errorf("P-256 signature is invalid")
	}
	return nil
}

func validateV4Transitions(
	groupID string, transitions []signedGroupTransition,
	initialTimestamp int64, initialPublicKey, initialHash, trustedHash string,
) (signedGroupTransition, error) {
	if len(transitions) == 0 {
		return signedGroupTransition{}, fmt.Errorf("group transition chain is empty")
	}
	first := transitions[0]
	if first.Timestamp != initialTimestamp || first.PublicKey != initialPublicKey || first.TransitionHash != initialHash {
		return signedGroupTransition{}, fmt.Errorf("transition chain does not start at the authenticated pairing state")
	}
	trustedSeen := false
	var previous *signedGroupTransition
	previousWasMarker := false
	for index := range transitions {
		transition := &transitions[index]
		if groupTransitionHash(groupID, *transition) != transition.TransitionHash {
			return signedGroupTransition{}, fmt.Errorf("group transition hash is invalid")
		}
		memberIDs := make(map[string]bool, len(transition.Members))
		for _, member := range transition.Members {
			if memberIDs[member.DeviceID] {
				return signedGroupTransition{}, fmt.Errorf("group transition members are duplicated")
			}
			memberIDs[member.DeviceID] = true
		}
		packageIDs := make(map[string]bool, len(transition.PackageDigests))
		for _, item := range transition.PackageDigests {
			if packageIDs[item.DeviceID] {
				return signedGroupTransition{}, fmt.Errorf("group transition package digests are duplicated")
			}
			packageIDs[item.DeviceID] = true
		}
		if len(memberIDs) != len(packageIDs) {
			return signedGroupTransition{}, fmt.Errorf("group transition package set is invalid")
		}
		for id := range memberIDs {
			if !packageIDs[id] {
				return signedGroupTransition{}, fmt.Errorf("group transition package set is invalid")
			}
		}
		currentIsMarker := false
		if previous != nil {
			removed := make([]transitionMember, 0)
			previousMembers := make(map[string]transitionMember, len(previous.Members))
			for _, member := range previous.Members {
				previousMembers[member.DeviceID] = member
				if !memberIDs[member.DeviceID] {
					removed = append(removed, member)
				}
			}
			for _, member := range transition.Members {
				if before, ok := previousMembers[member.DeviceID]; ok && before != member {
					return signedGroupTransition{}, fmt.Errorf("retained group member descriptor changed")
				}
			}
			actorRemoved := false
			for _, member := range removed {
				actorRemoved = actorRemoved || member.DeviceID == transition.ActorDeviceID
			}
			if actorRemoved {
				if len(removed) != 1 || transition.Recreated || transition.PublicKey != previous.PublicKey {
					return signedGroupTransition{}, fmt.Errorf("self-removal must be a same-key marker removing only its actor")
				}
				for _, member := range transition.Members {
					if _, ok := previousMembers[member.DeviceID]; !ok {
						return signedGroupTransition{}, fmt.Errorf("self-removal marker added a member")
					}
				}
			} else if len(removed) > 0 && (!transition.Recreated || transition.PublicKey == previous.PublicKey) {
				return signedGroupTransition{}, fmt.Errorf("removing another device must create a fresh group key")
			}
			currentIsMarker = actorRemoved
			if previousWasMarker {
				if !transition.Recreated || transition.PublicKey == previous.PublicKey || len(previousMembers) != len(memberIDs) {
					return signedGroupTransition{}, fmt.Errorf("removal marker was not followed by a fresh key for the same members")
				}
				for _, member := range transition.Members {
					if before, ok := previousMembers[member.DeviceID]; !ok || before != member {
						return signedGroupTransition{}, fmt.Errorf("removal marker changed members before fresh-key recovery")
					}
				}
			}
		}
		if previous != nil {
			if transition.PreviousHash != previous.TransitionHash || transition.Timestamp <= previous.Timestamp {
				return signedGroupTransition{}, fmt.Errorf("group transition chain is not contiguous")
			}
			var actor *transitionMember
			for i := range previous.Members {
				if previous.Members[i].DeviceID == transition.ActorDeviceID {
					actor = &previous.Members[i]
					break
				}
			}
			if actor == nil {
				return signedGroupTransition{}, fmt.Errorf("group transition actor is not authorized")
			}
			transcript := groupTransitionTranscript(groupID, *transition)
			if err := verifyP256Signature(actor.SigningPublicKey, transition.ActorSignature, transcript); err != nil {
				return signedGroupTransition{}, fmt.Errorf("verify group transition actor: %w", err)
			}
			if err := verifyP256Signature(previous.PublicKey, transition.ContinuitySignature, transcript); err != nil {
				return signedGroupTransition{}, fmt.Errorf("verify group transition continuity: %w", err)
			}
		} else if transition.PreviousHash == strings.Repeat("0", 64) {
			var actor *transitionMember
			for i := range transition.Members {
				if transition.Members[i].DeviceID == transition.ActorDeviceID {
					actor = &transition.Members[i]
					break
				}
			}
			if actor == nil {
				return signedGroupTransition{}, fmt.Errorf("genesis transition actor is not a member")
			}
			transcript := groupTransitionTranscript(groupID, *transition)
			if err := verifyP256Signature(actor.SigningPublicKey, transition.ActorSignature, transcript); err != nil {
				return signedGroupTransition{}, fmt.Errorf("verify genesis transition actor: %w", err)
			}
			if err := verifyP256Signature(transition.PublicKey, transition.ContinuitySignature, transcript); err != nil {
				return signedGroupTransition{}, fmt.Errorf("verify genesis transition continuity: %w", err)
			}
		}
		if transition.TransitionHash == trustedHash {
			trustedSeen = true
		}
		previous = transition
		previousWasMarker = currentIsMarker
	}
	if !trustedSeen {
		return signedGroupTransition{}, fmt.Errorf("previously trusted group transition is missing")
	}
	return transitions[len(transitions)-1], nil
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
