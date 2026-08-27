package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"notify.guru/internal/notify"
)

const instructions = "Create a notify.guru session for each agent task the user wants to follow. Show the returned local QR image URL when the browser runs on the same machine as notifyg; otherwise show the terminal QR code or pairing URL. Then wait for a device before sending events. Send status and notifications as work changes. A request may have multiple choices. Forward every response to the agent; notify.guru does not select or aggregate responses. Close a session only when immediate removal is intended; normal process exit leaves it to expire."

type Server struct {
	store  *notify.Store
	viewer *notify.QRViewer
}

func New(store *notify.Store, viewer *notify.QRViewer) *Server {
	return &Server{store: store, viewer: viewer}
}

func (s *Server) Run(ctx context.Context) error {
	server := mcp.NewServer(&mcp.Implementation{
		Name:        "notify-guru",
		Title:       "notify.guru",
		Description: "Ephemeral encrypted notifications between agent sessions and device groups",
		Version:     "0.1.0",
		WebsiteURL:  "https://notify.guru",
	}, &mcp.ServerOptions{Instructions: instructions})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "session_create",
		Description: "Create an ephemeral notification session and return the QR code used by a device group to join it.",
	}, s.create)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "session_pairing_create",
		Description: "Create another one-shot pairing QR code so an additional device group can join an existing session.",
	}, s.addPairing)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "session_wait_for_device",
		Description: "Wait until at least one device group has authenticated itself to a session.",
	}, s.waitForDevice)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "notify",
		Description: "Send an encrypted notification to every device group joined to a session.",
	}, s.notify)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "status",
		Description: "Update the encrypted current status shown on a session card without showing an OS notification.",
	}, s.status)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "session_color",
		Description: "Change the encrypted #rrggbb color of a session card, or choose another random pastel color.",
	}, s.color)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "request",
		Description: "Send an encrypted question with two or more choices to every joined device group.",
	}, s.request)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "request_close",
		Description: "End an open request on every joined device group.",
	}, s.closeRequest)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "responses_wait",
		Description: "Wait for and return every newly received encrypted response. The agent decides how to interpret them.",
	}, s.waitResponses)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "session_close",
		Description: "Immediately close a session and remove its card from devices. Do not call this for ordinary process exit.",
	}, s.close)

	return server.Run(ctx, &mcp.StdioTransport{})
}

type createInput struct {
	Title string `json:"title" jsonschema:"short title shown on the session card"`
	Color string `json:"color,omitempty" jsonschema:"optional panel color as #rrggbb; omit or use random to select from the pastel palette"`
}

type pairingOutput struct {
	SessionID  string `json:"session_id"`
	PairingURL string `json:"pairing_url"`
	QRCode     string `json:"qr_code"`
	QRImageURL string `json:"qr_image_url"`
}

func (s *Server) create(ctx context.Context, _ *mcp.CallToolRequest, input createInput) (*mcp.CallToolResult, pairingOutput, error) {
	sessionID, pairingURL, err := s.store.Create(ctx, input.Title, input.Color)
	if err != nil {
		return nil, pairingOutput{}, err
	}
	qr, err := notify.QRCode(pairingURL)
	if err != nil {
		return nil, pairingOutput{}, err
	}
	imageURL, err := s.viewer.Publish(pairingURL)
	if err != nil {
		return nil, pairingOutput{}, err
	}
	return nil, pairingOutput{SessionID: sessionID, PairingURL: pairingURL, QRCode: qr, QRImageURL: imageURL}, nil
}

type sessionInput struct {
	SessionID string `json:"session_id" jsonschema:"session identifier returned by session_create"`
}

func (s *Server) addPairing(ctx context.Context, _ *mcp.CallToolRequest, input sessionInput) (*mcp.CallToolResult, pairingOutput, error) {
	pairingURL, err := s.store.AddPairing(ctx, input.SessionID)
	if err != nil {
		return nil, pairingOutput{}, err
	}
	qr, err := notify.QRCode(pairingURL)
	if err != nil {
		return nil, pairingOutput{}, err
	}
	imageURL, err := s.viewer.Publish(pairingURL)
	if err != nil {
		return nil, pairingOutput{}, err
	}
	return nil, pairingOutput{SessionID: input.SessionID, PairingURL: pairingURL, QRCode: qr, QRImageURL: imageURL}, nil
}

type waitInput struct {
	SessionID     string `json:"session_id" jsonschema:"session identifier"`
	TimeoutSecond int    `json:"timeout_seconds" jsonschema:"maximum wait in seconds, from 1 through 600"`
}

type waitDeviceOutput struct {
	DeviceGroupCount int `json:"device_group_count"`
}

func (s *Server) waitForDevice(ctx context.Context, _ *mcp.CallToolRequest, input waitInput) (*mcp.CallToolResult, waitDeviceOutput, error) {
	timeout, err := timeoutDuration(input.TimeoutSecond)
	if err != nil {
		return nil, waitDeviceOutput{}, err
	}
	count, err := s.store.WaitForGroups(ctx, input.SessionID, timeout)
	if err != nil {
		return nil, waitDeviceOutput{}, err
	}
	return nil, waitDeviceOutput{DeviceGroupCount: count}, nil
}

type messageInput struct {
	SessionID string `json:"session_id" jsonschema:"session identifier"`
	Message   string `json:"message" jsonschema:"notification body"`
}

type deliveredOutput struct {
	Delivered bool `json:"delivered"`
}

func (s *Server) notify(ctx context.Context, _ *mcp.CallToolRequest, input messageInput) (*mcp.CallToolResult, deliveredOutput, error) {
	if err := s.store.SendNotify(ctx, input.SessionID, input.Message); err != nil {
		return nil, deliveredOutput{}, err
	}
	return nil, deliveredOutput{Delivered: true}, nil
}

type statusInput struct {
	SessionID string `json:"session_id" jsonschema:"session identifier"`
	Status    string `json:"status" jsonschema:"current status"`
}

func (s *Server) status(ctx context.Context, _ *mcp.CallToolRequest, input statusInput) (*mcp.CallToolResult, deliveredOutput, error) {
	if err := s.store.SendStatus(ctx, input.SessionID, input.Status); err != nil {
		return nil, deliveredOutput{}, err
	}
	return nil, deliveredOutput{Delivered: true}, nil
}

type colorInput struct {
	SessionID string `json:"session_id" jsonschema:"session identifier"`
	Color     string `json:"color" jsonschema:"panel color as #rrggbb or random"`
}

func (s *Server) color(ctx context.Context, _ *mcp.CallToolRequest, input colorInput) (*mcp.CallToolResult, deliveredOutput, error) {
	if err := s.store.SetColor(ctx, input.SessionID, input.Color); err != nil {
		return nil, deliveredOutput{}, err
	}
	return nil, deliveredOutput{Delivered: true}, nil
}

type requestInput struct {
	SessionID string   `json:"session_id" jsonschema:"session identifier"`
	Prompt    string   `json:"prompt" jsonschema:"question shown to the device group"`
	Options   []string `json:"options" jsonschema:"two or more choice labels"`
}

type requestOutput struct {
	RequestID string          `json:"request_id"`
	Choices   []notify.Choice `json:"choices"`
}

func (s *Server) request(ctx context.Context, _ *mcp.CallToolRequest, input requestInput) (*mcp.CallToolResult, requestOutput, error) {
	requestID, choices, err := s.store.SendRequest(ctx, input.SessionID, input.Prompt, input.Options)
	if err != nil {
		return nil, requestOutput{}, err
	}
	return nil, requestOutput{RequestID: requestID, Choices: choices}, nil
}

type closeRequestInput struct {
	SessionID string `json:"session_id" jsonschema:"session identifier"`
	RequestID string `json:"request_id" jsonschema:"request identifier returned by request"`
}

func (s *Server) closeRequest(ctx context.Context, _ *mcp.CallToolRequest, input closeRequestInput) (*mcp.CallToolResult, closeOutput, error) {
	if err := s.store.CloseRequest(ctx, input.SessionID, input.RequestID); err != nil {
		return nil, closeOutput{}, err
	}
	return nil, closeOutput{Closed: true}, nil
}

type responsesOutput struct {
	Responses []notify.Response `json:"responses"`
}

func (s *Server) waitResponses(ctx context.Context, _ *mcp.CallToolRequest, input waitInput) (*mcp.CallToolResult, responsesOutput, error) {
	timeout, err := timeoutDuration(input.TimeoutSecond)
	if err != nil {
		return nil, responsesOutput{}, err
	}
	responses, err := s.store.WaitResponses(ctx, input.SessionID, timeout)
	if err != nil {
		return nil, responsesOutput{}, err
	}
	return nil, responsesOutput{Responses: responses}, nil
}

type closeOutput struct {
	Closed bool `json:"closed"`
}

func (s *Server) close(ctx context.Context, _ *mcp.CallToolRequest, input sessionInput) (*mcp.CallToolResult, closeOutput, error) {
	if err := s.store.Close(ctx, input.SessionID); err != nil {
		return nil, closeOutput{}, err
	}
	return nil, closeOutput{Closed: true}, nil
}

func timeoutDuration(seconds int) (time.Duration, error) {
	if seconds < 1 || seconds > 600 {
		return 0, fmt.Errorf("timeout_seconds must be between 1 and 600")
	}
	return time.Duration(seconds) * time.Second, nil
}
