package main

import (
	"bytes"
	"testing"
	"time"

	"notify.guru/internal/notify"
)

func TestWriteResponseIdentifiesTrackedDismissTarget(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writeResponse(&output, notify.Response{
		Type:      "dismiss",
		ItemID:    "notification-item",
		EventID:   "notification-item",
		GroupID:   "group",
		CreatedAt: time.Date(2026, 8, 28, 3, 24, 36, 0, time.UTC),
	})
	if got, want := output.String(), "dismiss item=notification-item group=group at=2026-08-28T03:24:36Z\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteResponseKeepsLegacyRequestDismissReadable(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writeResponse(&output, notify.Response{
		Type:      "dismiss",
		RequestID: "request",
		GroupID:   "group",
		CreatedAt: time.Date(2026, 8, 28, 3, 24, 36, 0, time.UTC),
	})
	if got, want := output.String(), "dismiss request=request group=group at=2026-08-28T03:24:36Z\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestWriteResponseIncludesDecryptedAttachmentPath(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	writeResponse(&output, notify.Response{
		Type:       "feedback",
		GroupID:    "group",
		Attachment: &notify.ReceivedAttachment{Path: "/tmp/notifyg-attachments/example.jpg"},
		CreatedAt:  time.Date(2026, 9, 3, 11, 38, 38, 0, time.UTC),
	})
	if got, want := output.String(), "feedback message=\"\" attachment=/tmp/notifyg-attachments/example.jpg group=group at=2026-09-03T11:38:38Z\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}
