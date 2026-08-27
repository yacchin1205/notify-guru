package notify

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestQRViewerServesAnInMemoryImageAtAnOpaqueLoopbackURL(t *testing.T) {
	viewer, err := NewQRViewer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := viewer.Close(); err != nil {
			t.Error(err)
		}
	})

	pairingURL := "https://notify.guru/join#v=1&s=session&p=pairing&t=secret"
	imageURL, err := viewer.Publish(pairingURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(imageURL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" {
		t.Fatalf("viewer URL = %q, want an HTTP IPv4 loopback URL", imageURL)
	}
	if bytes.Contains([]byte(imageURL), []byte("session")) || bytes.Contains([]byte(imageURL), []byte("secret")) {
		t.Fatalf("viewer URL exposes pairing data: %q", imageURL)
	}

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(imageURL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if response.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("Content-Type = %q, want image/png", response.Header.Get("Content-Type"))
	}
	for name, want := range map[string]string{
		"Cache-Control":                "no-store",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Referrer-Policy":              "no-referrer",
		"X-Content-Type-Options":       "nosniff",
	} {
		if got := response.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	image := make([]byte, 8)
	if _, err := response.Body.Read(image); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(image, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("image does not start with the PNG signature: %x", image)
	}
}

func TestQRViewerRejectsOtherHostsAndExpiredPaths(t *testing.T) {
	viewer, err := NewQRViewer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := viewer.Close(); err != nil {
			t.Error(err)
		}
	})

	imageURL, err := viewer.Publish("https://notify.guru/join#secret")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, imageURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "attacker.example"
	client := &http.Client{Timeout: time.Second}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Host status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}

	parsed, err := url.Parse(imageURL)
	if err != nil {
		t.Fatal(err)
	}
	viewer.mu.Lock()
	viewer.entries[parsed.Path].expiresAt = time.Now().Add(-time.Second)
	viewer.mu.Unlock()
	response, err = client.Get(imageURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expired path status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
}

func TestQRViewerReportsAnUnexpectedListenerFailure(t *testing.T) {
	viewer, err := NewQRViewer()
	if err != nil {
		t.Fatal(err)
	}
	if err := viewer.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := viewer.Wait(); err == nil {
		t.Fatal("unexpected listener failure was not reported")
	}
	if err := viewer.Close(); err == nil {
		t.Fatal("Close did not retain the listener failure")
	}
}
