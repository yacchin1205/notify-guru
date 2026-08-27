package notify

import "time"

type Pairing struct {
	ID         string
	Token      string
	AuthSecret string
}

type Group struct {
	ID  string
	Key []byte
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

func eventAAD(sessionID, groupID, eventID string) string {
	return "notify.guru/v1/event/" + sessionID + "/" + groupID + "/" + eventID
}

func responseAAD(sessionID, groupID, responseID string) string {
	return "notify.guru/v1/response/" + sessionID + "/" + groupID + "/" + responseID
}
