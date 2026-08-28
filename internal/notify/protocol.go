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
}

type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Response struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	ItemID    string    `json:"itemId,omitempty"`
	RequestID string    `json:"requestId,omitempty"`
	EventID   string    `json:"eventId,omitempty"`
	OptionID  string    `json:"optionId,omitempty"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	GroupID   string    `json:"groupId"`
}

type decryptedResponse struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	RequestID string    `json:"requestId,omitempty"`
	EventID   string    `json:"eventId,omitempty"`
	OptionID  string    `json:"optionId,omitempty"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
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

func eventAAD(sessionID, groupID, eventID string, timestamp int64) string {
	return fmt.Sprintf("notify.guru/v3/event/%s/%s/%d/%s", sessionID, groupID, timestamp, eventID)
}

func responseAAD(sessionID, groupID, responseID string, timestamp int64) string {
	return fmt.Sprintf("notify.guru/v3/response/%s/%s/%d/%s", sessionID, groupID, timestamp, responseID)
}
