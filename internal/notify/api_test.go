package notify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestIsTransientAPIError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "request timeout", err: &APIError{Status: 408}, want: true},
		{name: "too many requests", err: &APIError{Status: 429}, want: true},
		{name: "server error", err: &APIError{Status: 503}, want: true},
		{name: "transport error", err: &transientAPIError{err: errors.New("connection reset")}, want: true},
		{name: "client timeout", err: context.DeadlineExceeded, want: true},
		{name: "invalid request", err: &APIError{Status: 400}, want: false},
		{name: "conflict", err: &APIError{Status: 409}, want: false},
		{name: "unexpected local error", err: errors.New("unexpected"), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := IsTransientAPIError(context.Background(), test.err); got != test.want {
				t.Fatalf("IsTransientAPIError() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestIsTransientAPIErrorDoesNotRetryAfterCallerCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := &transientAPIError{err: context.Canceled}
	if IsTransientAPIError(ctx, err) {
		t.Fatal("caller cancellation was classified as transient")
	}
}

func TestAPIClassifiesAnInvalidErrorResponseByItsHTTPStatus(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		status int
		want   bool
	}{
		{status: 503, want: true},
		{status: 400, want: false},
	} {
		api, err := NewAPI("https://notify.guru")
		if err != nil {
			t.Fatal(err)
		}
		api.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: test.status,
				Body:       io.NopCloser(strings.NewReader("not JSON")),
			}, nil
		})
		err = api.do(context.Background(), http.MethodGet, "/test", "", nil, nil)
		if err == nil {
			t.Fatalf("status %d with an invalid body returned no error", test.status)
		}
		if got := IsTransientAPIError(context.Background(), err); got != test.want {
			t.Fatalf("status %d transient = %t, want %t (error: %v)", test.status, got, test.want, err)
		}
	}
}
