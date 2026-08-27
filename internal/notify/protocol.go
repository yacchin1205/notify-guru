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
	ID                string
	PairingID         string
	InitialRevision   int64
	InitialGeneration int64
	InitialPublicKey  string
	Revision          int64
	Generation        int64
	PublicKey         string
	Keys              map[int64][]byte
}

type GenerationTransition struct {
	Revision            int64  `json:"revision"`
	PreviousGeneration  int64  `json:"previousGeneration"`
	Generation          int64  `json:"generation"`
	GenerationPublicKey string `json:"generationPublicKey"`
	Action              string `json:"action"`
	ActorDeviceID       string `json:"actorDeviceId"`
	TargetDeviceID      string `json:"targetDeviceId"`
	PackagesHash        string `json:"packagesHash"`
	GroupSignature      string `json:"groupSignature"`
	DeviceSignature     string `json:"deviceSignature"`
	CreatedAt           int64  `json:"createdAt"`
}

type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type Response struct {
	ID        string    `json:"id"`
	RequestID string    `json:"requestId"`
	OptionID  string    `json:"optionId"`
	CreatedAt time.Time `json:"createdAt"`
	GroupID   string    `json:"groupId"`
}

type decryptedResponse struct {
	ID        string    `json:"id"`
	RequestID string    `json:"requestId"`
	OptionID  string    `json:"optionId"`
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
	CreatedAt    time.Time `json:"createdAt"`
}

func eventAAD(sessionID, groupID, eventID string, generation int64) string {
	return fmt.Sprintf("notify.guru/v2/event/%s/%s/%d/%s", sessionID, groupID, generation, eventID)
}

func responseAAD(sessionID, groupID, responseID string, generation int64) string {
	return fmt.Sprintf("notify.guru/v2/response/%s/%s/%d/%s", sessionID, groupID, generation, responseID)
}
