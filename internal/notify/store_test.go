package notify

import (
	"net/url"
	"testing"
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

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
