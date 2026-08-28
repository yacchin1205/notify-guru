package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 2 << 20

type API struct {
	baseURL *url.URL
	client  *http.Client
}

type APIError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

type transientAPIError struct {
	err error
}

func (e *APIError) Error() string {
	return fmt.Sprintf("notify.guru API: %s (%d): %s", e.Code, e.Status, e.Message)
}

func (e *transientAPIError) Error() string {
	return e.err.Error()
}

func (e *transientAPIError) Unwrap() error {
	return e.err
}

func IsTransientAPIError(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	var apiError *APIError
	if errors.As(err, &apiError) {
		return isTransientHTTPStatus(apiError.Status)
	}
	var transientError *transientAPIError
	return errors.As(err, &transientError) || errors.Is(err, context.DeadlineExceeded)
}

func isTransientHTTPStatus(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError
}

func NewAPI(rawURL string) (*API, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	if baseURL.Scheme != "https" && !(baseURL.Scheme == "http" && (baseURL.Hostname() == "localhost" || baseURL.Hostname() == "127.0.0.1")) {
		return nil, fmt.Errorf("base URL must use HTTPS, except for localhost")
	}
	if baseURL.Host == "" || (baseURL.Path != "" && baseURL.Path != "/") || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("base URL must contain only scheme and host")
	}
	baseURL.Path = ""
	return &API{baseURL: baseURL, client: &http.Client{Timeout: 20 * time.Second}}, nil
}

func (a *API) JoinURL(sessionID string, pairing Pairing, creatorPublicKey, color string) string {
	joinURL := *a.baseURL
	joinURL.Path = "/join"
	fragment := url.Values{}
	fragment.Set("v", "3")
	fragment.Set("s", sessionID)
	fragment.Set("p", pairing.ID)
	fragment.Set("t", pairing.Token)
	fragment.Set("a", pairing.AuthSecret)
	fragment.Set("k", creatorPublicKey)
	fragment.Set("c", strings.TrimPrefix(color, "#"))
	joinURL.Fragment = fragment.Encode()
	return joinURL.String()
}

func (a *API) createSession(ctx context.Context, sessionID, managerHash, publicKey string, pairing Pairing) error {
	request := struct {
		SessionID        string `json:"sessionId"`
		ManagerTokenHash string `json:"managerTokenHash"`
		CreatorPublicKey string `json:"creatorPublicKey"`
		Pairing          struct {
			ID        string `json:"id"`
			TokenHash string `json:"tokenHash"`
		} `json:"pairing"`
	}{SessionID: sessionID, ManagerTokenHash: managerHash, CreatorPublicKey: publicKey}
	request.Pairing.ID = pairing.ID
	request.Pairing.TokenHash = tokenHash(pairing.Token)
	return a.do(ctx, http.MethodPost, "/api/sessions", "", request, &struct {
		ExpiresAt int64 `json:"expiresAt"`
	}{})
}

func (a *API) addPairing(ctx context.Context, sessionID, managerToken string, pairing Pairing) error {
	request := struct {
		ID        string `json:"id"`
		TokenHash string `json:"tokenHash"`
	}{ID: pairing.ID, TokenHash: tokenHash(pairing.Token)}
	return a.do(ctx, http.MethodPost, "/api/sessions/"+sessionID+"/pairings", managerToken, request, &struct {
		Created bool `json:"created"`
	}{})
}

type currentGroupKey struct {
	Timestamp int64    `json:"timestamp"`
	PublicKey string   `json:"publicKey"`
	Members   []string `json:"members"`
}

type joinsResult struct {
	Groups []struct {
		Sequence            int64            `json:"sequence"`
		GroupID             string           `json:"groupId"`
		PairingID           string           `json:"pairingId"`
		InitialKeyTimestamp int64            `json:"initialKeyTimestamp"`
		InitialPublicKey    string           `json:"initialPublicKey"`
		Proof               string           `json:"proof"`
		JoinedAt            int64            `json:"joinedAt"`
		Key                 *currentGroupKey `json:"key"`
	} `json:"groups"`
	ExpiresAt int64 `json:"expiresAt"`
}

func (a *API) joins(ctx context.Context, sessionID, managerToken string) (joinsResult, error) {
	var result joinsResult
	err := a.do(ctx, http.MethodGet, "/api/sessions/"+sessionID+"/joins", managerToken, nil, &result)
	return result, err
}

func (a *API) addEvent(ctx context.Context, sessionID, managerToken, eventID, itemID, groupID string, timestamp int64, nonce, ciphertext, notificationKind string) error {
	request := struct {
		EventID          string `json:"eventId"`
		ItemID           string `json:"itemId,omitempty"`
		GroupID          string `json:"groupId"`
		KeyTimestamp     int64  `json:"keyTimestamp"`
		Nonce            string `json:"nonce"`
		Ciphertext       string `json:"ciphertext"`
		NotificationKind string `json:"notificationKind"`
	}{eventID, itemID, groupID, timestamp, nonce, ciphertext, notificationKind}
	return a.do(ctx, http.MethodPost, "/api/sessions/"+sessionID+"/events", managerToken, request, &struct {
		ExpiresAt int64 `json:"expiresAt"`
	}{})
}

type responsesResult struct {
	Responses []struct {
		Sequence     int64  `json:"sequence"`
		ResponseID   string `json:"responseId"`
		ItemID       string `json:"itemId"`
		GroupID      string `json:"groupId"`
		KeyTimestamp int64  `json:"keyTimestamp"`
		Nonce        string `json:"nonce"`
		Ciphertext   string `json:"ciphertext"`
		CreatedAt    int64  `json:"createdAt"`
	} `json:"responses"`
	ExpiresAt int64 `json:"expiresAt"`
}

func (a *API) responses(ctx context.Context, sessionID, managerToken string, after int64) (responsesResult, error) {
	var result responsesResult
	err := a.do(ctx, http.MethodGet, fmt.Sprintf("/api/sessions/%s/responses?after=%d", sessionID, after), managerToken, nil, &result)
	return result, err
}

func (a *API) closeSession(ctx context.Context, sessionID, managerToken string) error {
	return a.do(ctx, http.MethodDelete, "/api/sessions/"+sessionID, managerToken, nil, nil)
}

func (a *API) do(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, a.baseURL.String()+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return &transientAPIError{err: err}
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return &transientAPIError{err: err}
	}
	if len(responseBody) > maxResponseBytes {
		return fmt.Errorf("API response exceeds %d bytes", maxResponseBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var apiError APIError
		if err := decodeJSON(responseBody, &apiError); err != nil {
			decodeErr := fmt.Errorf("decode API error with status %d: %w", response.StatusCode, err)
			if isTransientHTTPStatus(response.StatusCode) {
				return &transientAPIError{err: decodeErr}
			}
			return decodeErr
		}
		apiError.Status = response.StatusCode
		return &apiError
	}
	if output == nil {
		if len(responseBody) != 0 {
			return fmt.Errorf("API returned an unexpected response body")
		}
		return nil
	}
	return decodeJSON(responseBody, output)
}

func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateText(name, value string, max int) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if len(value) > max {
		return fmt.Errorf("%s exceeds %d bytes", name, max)
	}
	return nil
}
