package notify

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

func QRCode(value string) (string, error) {
	code, err := qrcode.New(value, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("create QR code: %w", err)
	}
	return code.ToSmallString(false), nil
}

func QRCodePNG(value string) ([]byte, error) {
	image, err := qrcode.Encode(value, qrcode.Medium, 768)
	if err != nil {
		return nil, fmt.Errorf("create QR code image: %w", err)
	}
	return image, nil
}
