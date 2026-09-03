package notify

import (
	"fmt"
	"time"
)

type Pairing struct {
	ID         string
	Token      string
	AuthSecret string
}

type Group struct {
	ID               string
	PairingID        string
	InitialTimestamp int64
	InitialPublicKey string
	Timestamp        int64
	PublicKey        string
	Keys             map[int64][]byte
	PublicKeys       map[int64]string
}

type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Response struct {
	ID         string              `json:"id"`
	Type       string              `json:"type"`
	ItemID     string              `json:"itemId,omitempty"`
	RequestID  string              `json:"requestId,omitempty"`
	EventID    string              `json:"eventId,omitempty"`
	OptionID   string              `json:"optionId,omitempty"`
	Message    string              `json:"message,omitempty"`
	CreatedAt  time.Time           `json:"createdAt"`
	GroupID    string              `json:"groupId"`
	Attachment *ReceivedAttachment `json:"attachment,omitempty"`
}

type ReceivedAttachment struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	MediaType  string `json:"mediaType"`
	ByteLength int64  `json:"byteLength"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	Path       string `json:"path"`
	URI        string `json:"uri"`
}

type attachmentManifest struct {
	ID               string `json:"id"`
	Kind             string `json:"kind"`
	MediaType        string `json:"mediaType"`
	ByteLength       int64  `json:"byteLength"`
	Width            int    `json:"width"`
	Height           int    `json:"height"`
	Nonce            string `json:"nonce"`
	CiphertextLength int64  `json:"ciphertextLength"`
	CiphertextSHA256 string `json:"ciphertextSha256"`
}

type decryptedResponse struct {
	ID         string              `json:"id"`
	Type       string              `json:"type"`
	RequestID  string              `json:"requestId,omitempty"`
	EventID    string              `json:"eventId,omitempty"`
	OptionID   string              `json:"optionId,omitempty"`
	Message    string              `json:"message,omitempty"`
	Attachment *attachmentManifest `json:"attachment,omitempty"`
	CreatedAt  time.Time           `json:"createdAt"`
}

type event struct {
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	SessionTitle string    `json:"sessionTitle"`
	Message      string    `json:"message,omitempty"`
	Status       string    `json:"status,omitempty"`
	RequestID    string    `json:"requestId,omitempty"`
	Prompt       string    `json:"prompt,omitempty"`
	Options      []Choice  `json:"options,omitempty"`
	Color        string    `json:"color"`
	CreatedAt    time.Time `json:"createdAt"`
}

func eventAAD(version int, sessionID, groupID, eventID string, timestamp int64) string {
	return fmt.Sprintf("notify.guru/v%d/event/%s/%s/%d/%s", version, sessionID, groupID, timestamp, eventID)
}

func responseAAD(version int, sessionID, groupID, responseID string, timestamp int64) string {
	return fmt.Sprintf("notify.guru/v%d/response/%s/%s/%d/%s", version, sessionID, groupID, timestamp, responseID)
}

func attachmentAAD(sessionID, groupID, responseID, attachmentID string, timestamp int64) string {
	return fmt.Sprintf("notify.guru/v4/attachment/%s/%s/%d/%s/%s", sessionID, groupID, timestamp, responseID, attachmentID)
}
