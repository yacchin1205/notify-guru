package notify

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestResolveColor(t *testing.T) {
	t.Parallel()

	for range 100 {
		color, err := resolveColor("random")
		if err != nil {
			t.Fatal(err)
		}
		if !contains(pastelPalette, color) {
			t.Fatalf("random color %q is not in the pastel palette", color)
		}
	}
	color, err := resolveColor("#A1B2C3")
	if err != nil {
		t.Fatal(err)
	}
	if color != "#a1b2c3" {
		t.Fatalf("normalized color = %q", color)
	}
	if _, err := resolveColor("red"); err == nil {
		t.Fatal("named color was accepted")
	}
}

func TestJoinURLCarriesInitialColorInTheFragment(t *testing.T) {
	t.Parallel()
	api, err := NewAPI("https://notify.guru")
	if err != nil {
		t.Fatal(err)
	}
	value := api.JoinURL("session", Pairing{ID: "pairing", Token: "token", AuthSecret: "secret"}, "public", "#ffd6e0")
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	if fields.Get("c") != "ffd6e0" {
		t.Fatalf("fragment color = %q", fields.Get("c"))
	}
}

func TestEventItemIDUsesTheLogicalItemIdentifier(t *testing.T) {
	t.Parallel()

	notifyID, err := eventItemID(event{ID: "notification", Type: "notify"}, "notify")
	if err != nil {
		t.Fatal(err)
	}
	if notifyID != "notification" {
		t.Fatalf("notify item ID = %q", notifyID)
	}

	requestID, err := eventItemID(event{ID: "envelope-payload", Type: "request", RequestID: "request"}, "request")
	if err != nil {
		t.Fatal(err)
	}
	if requestID != "request" {
		t.Fatalf("request item ID = %q", requestID)
	}

	if _, err := eventItemID(event{ID: "status", Type: "status"}, "notify"); err == nil {
		t.Fatal("status event was accepted as a notification item")
	}
}

func TestEventRetrySchedule(t *testing.T) {
	t.Parallel()

	want := [...]time.Duration{5 * time.Second, 30 * time.Second}
	if eventRetryDelays != want {
		t.Fatalf("event retry delays = %v, want %v", eventRetryDelays, want)
	}
}

func TestRetryEventOperationRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := retryEventOperation(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		if attempts < 3 {
			return &APIError{Status: 503, Code: "unavailable", Message: "temporarily unavailable"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("attempt count = %d, want 3", attempts)
	}
}

func TestRetryEventOperationReturnsTheLastTransientFailure(t *testing.T) {
	t.Parallel()

	attempts := 0
	want := &APIError{Status: 503, Code: "unavailable", Message: "temporarily unavailable"}
	err := retryEventOperation(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if attempts != 3 {
		t.Fatalf("attempt count = %d, want 3", attempts)
	}
}

func TestRetryEventOperationDoesNotRetryPermanentFailure(t *testing.T) {
	t.Parallel()

	attempts := 0
	want := &APIError{Status: 403, Code: "forbidden", Message: "forbidden"}
	err := retryEventOperation(context.Background(), []time.Duration{0, 0}, func() error {
		attempts++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if attempts != 1 {
		t.Fatalf("attempt count = %d, want 1", attempts)
	}
}

func TestRetryEventOperationStopsWhenTheCallerCancels(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := retryEventOperation(ctx, []time.Duration{time.Hour, time.Hour}, func() error {
		attempts++
		cancel()
		return &transientAPIError{err: context.Canceled}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
	if attempts != 1 {
		t.Fatalf("attempt count = %d, want 1", attempts)
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
