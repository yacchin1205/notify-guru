package notify

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

const qrViewerLifetime = 10 * time.Minute

type qrViewerEntry struct {
	image     []byte
	expiresAt time.Time
	timer     *time.Timer
}

type QRViewer struct {
	listener net.Listener
	server   *http.Server
	host     string

	mu       sync.Mutex
	entries  map[string]*qrViewerEntry
	closed   bool
	serveErr error
	done     chan struct{}
}

func NewQRViewer() (*QRViewer, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for QR code viewer: %w", err)
	}
	viewer := &QRViewer{
		listener: listener,
		host:     listener.Addr().String(),
		entries:  make(map[string]*qrViewerEntry),
		done:     make(chan struct{}),
	}
	viewer.server = &http.Server{
		Handler:           viewer,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	go viewer.serve()
	return viewer, nil
}

func (v *QRViewer) Publish(value string) (string, error) {
	image, err := QRCodePNG(value)
	if err != nil {
		return "", err
	}
	token, err := randomValue(24)
	if err != nil {
		return "", fmt.Errorf("create QR code viewer path: %w", err)
	}
	path := "/qr/" + token

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return "", fmt.Errorf("QR code viewer is closed")
	}
	if v.serveErr != nil {
		return "", fmt.Errorf("serve QR code viewer: %w", v.serveErr)
	}
	if _, exists := v.entries[path]; exists {
		return "", fmt.Errorf("QR code viewer path collision")
	}
	entry := &qrViewerEntry{image: image, expiresAt: time.Now().Add(qrViewerLifetime)}
	entry.timer = time.AfterFunc(qrViewerLifetime, func() {
		v.mu.Lock()
		delete(v.entries, path)
		v.mu.Unlock()
	})
	v.entries[path] = entry
	return "http://" + v.host + path, nil
}

func (v *QRViewer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox")
	response.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")

	if request.Host != v.host || !isLoopbackAddress(request.RemoteAddr) {
		http.Error(response, "forbidden", http.StatusForbidden)
		return
	}
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if request.URL.RawQuery != "" {
		http.NotFound(response, request)
		return
	}

	v.mu.Lock()
	entry, exists := v.entries[request.URL.Path]
	if exists && !time.Now().Before(entry.expiresAt) {
		entry.timer.Stop()
		delete(v.entries, request.URL.Path)
		exists = false
	}
	v.mu.Unlock()
	if !exists {
		http.NotFound(response, request)
		return
	}

	response.Header().Set("Content-Type", "image/png")
	response.WriteHeader(http.StatusOK)
	if _, err := response.Write(entry.image); err != nil {
		return
	}
}

func (v *QRViewer) Close() error {
	v.mu.Lock()
	if v.closed {
		v.mu.Unlock()
		<-v.done
		return v.serveError()
	}
	v.closed = true
	for path, entry := range v.entries {
		entry.timer.Stop()
		delete(v.entries, path)
	}
	v.mu.Unlock()

	listenerErr := v.listener.Close()
	if errors.Is(listenerErr, net.ErrClosed) {
		listenerErr = nil
	}
	closeErr := v.server.Close()
	if errors.Is(closeErr, http.ErrServerClosed) || errors.Is(closeErr, net.ErrClosed) {
		closeErr = nil
	}
	<-v.done
	return errors.Join(listenerErr, closeErr, v.serveError())
}

func (v *QRViewer) Done() <-chan struct{} {
	return v.done
}

func (v *QRViewer) Wait() error {
	<-v.done
	return v.serveError()
}

func (v *QRViewer) serve() {
	err := v.server.Serve(v.listener)
	v.mu.Lock()
	if v.closed && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
		err = nil
	}
	v.serveErr = err
	v.mu.Unlock()
	close(v.done)
}

func (v *QRViewer) serveError() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.serveErr == nil {
		return nil
	}
	return fmt.Errorf("serve QR code viewer: %w", v.serveErr)
}

func isLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
