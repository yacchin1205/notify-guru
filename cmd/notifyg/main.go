package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"notify.guru/internal/mcpserver"
	"notify.guru/internal/notify"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	flags := flag.NewFlagSet("notifyg", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseURL := flags.String("base-url", "https://notify.guru", "notify.guru service URL")
	title := flags.String("title", "Development session", "interactive session title")
	color := flags.String("color", "random", "session panel color: random or #rrggbb")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return fmt.Errorf("usage: notifyg [--base-url URL] [--title TITLE] [--color random|#rrggbb] [mcp]")
	}

	api, err := notify.NewAPI(*baseURL)
	if err != nil {
		return err
	}
	store := notify.NewStore(api)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	viewer, err := notify.NewQRViewer()
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, viewer.Close())
	}()

	operation := func(ctx context.Context) error {
		if flags.NArg() == 1 {
			if flags.Arg(0) != "mcp" {
				return fmt.Errorf("unknown mode %q", flags.Arg(0))
			}
			return mcpserver.New(store, viewer).Run(ctx)
		}
		return interactive(ctx, store, viewer, *title, *color, os.Stdin, os.Stdout, os.Stderr)
	}
	err = supervise(ctx, viewer, operation)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func supervise(ctx context.Context, viewer *notify.QRViewer, operation func(context.Context) error) error {
	operationCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- operation(operationCtx)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-viewer.Done():
		if err := viewer.Wait(); err != nil {
			return err
		}
		return fmt.Errorf("QR code viewer stopped unexpectedly")
	}
}

func interactive(ctx context.Context, store *notify.Store, viewer *notify.QRViewer, title, color string, input io.Reader, output, errorOutput io.Writer) error {
	sessionID, pairingURL, err := store.Create(ctx, title, color)
	if err != nil {
		return err
	}
	qr, err := notify.QRCode(pairingURL)
	if err != nil {
		return err
	}
	imageURL, err := viewer.Publish(pairingURL)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Session: %s\n%s\n%s\nQR image: %s\n", sessionID, qr, pairingURL, imageURL)
	fmt.Fprintln(output, "Commands: join, pair, notify TEXT, status TEXT, color #rrggbb|random, request PROMPT | OPTION | OPTION, close-request REQUEST_ID, responses, close, quit")

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 300_000)
	lines := make(chan string)
	scanDone := make(chan error, 1)
	go func() {
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		scanDone <- scanner.Err()
	}()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	knownGroups := 0
	fmt.Fprint(output, "notifyg> ")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-scanDone:
			return err
		case <-ticker.C:
			count, err := store.RefreshGroups(ctx, sessionID)
			if err != nil {
				if notify.IsTransientAPIError(ctx, err) {
					fmt.Fprintf(errorOutput, "\ntemporarily unable to check joined device groups: %v; will retry\n", err)
					fmt.Fprint(output, "notifyg> ")
					continue
				}
				return fmt.Errorf("detect joined device groups: %w", err)
			}
			if count > knownGroups {
				fmt.Fprintf(output, "\n%d new device group(s) joined; %d total\nnotifyg> ", count-knownGroups, count)
				knownGroups = count
			}
			continue
		case scanned := <-lines:
			line := strings.TrimSpace(scanned)
			if line == "" {
				fmt.Fprint(output, "notifyg> ")
				continue
			}
			command, argument, _ := strings.Cut(line, " ")
			exit, err := runCommand(ctx, store, viewer, sessionID, command, argument, &knownGroups, output, errorOutput)
			if err != nil {
				return err
			}
			if exit {
				return nil
			}
			fmt.Fprint(output, "notifyg> ")
		}
	}
}

func runCommand(ctx context.Context, store *notify.Store, viewer *notify.QRViewer, sessionID, command, argument string, knownGroups *int, output, errorOutput io.Writer) (bool, error) {
	switch command {
	case "join":
		count, err := store.RefreshGroups(ctx, sessionID)
		if err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		*knownGroups = count
		fmt.Fprintf(output, "%d device group(s) joined\n", count)
	case "pair":
		url, err := store.AddPairing(ctx, sessionID)
		if err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		qr, err := notify.QRCode(url)
		if err != nil {
			return false, err
		}
		imageURL, err := viewer.Publish(url)
		if err != nil {
			return false, err
		}
		fmt.Fprintf(output, "%s\n%s\nQR image: %s\n", qr, url, imageURL)
	case "notify":
		itemID, err := store.SendNotify(ctx, sessionID, argument)
		if err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		fmt.Fprintf(output, "notification item=%s sent\n", itemID)
	case "status":
		if err := store.SendStatus(ctx, sessionID, argument); err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		fmt.Fprintln(output, "sent")
	case "color":
		if err := store.SetColor(ctx, sessionID, argument); err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		fmt.Fprintln(output, "color changed")
	case "request":
		parts := strings.Split(argument, "|")
		if len(parts) < 3 {
			fmt.Fprintln(errorOutput, "request requires a prompt and at least two options separated by |")
			return false, nil
		}
		for index := range parts {
			parts[index] = strings.TrimSpace(parts[index])
		}
		requestID, choices, err := store.SendRequest(ctx, sessionID, parts[0], parts[1:])
		if err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		fmt.Fprintf(output, "request %s sent: %v\n", requestID, choices)
	case "close-request":
		if err := store.CloseRequest(ctx, sessionID, argument); err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		fmt.Fprintln(output, "request closed")
	case "responses":
		responses, err := store.Responses(ctx, sessionID)
		if err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		for _, response := range responses {
			writeResponse(output, response)
		}
	case "close":
		if err := store.Close(ctx, sessionID); err != nil {
			fmt.Fprintln(errorOutput, err)
			return false, nil
		}
		fmt.Fprintln(output, "closed")
		return true, nil
	case "quit":
		return true, nil
	default:
		fmt.Fprintf(errorOutput, "unknown command %q\n", command)
	}
	return false, nil
}

func writeResponse(output io.Writer, response notify.Response) {
	timestamp := response.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
	switch response.Type {
	case "feedback":
		fmt.Fprintf(output, "feedback message=%q group=%s at=%s\n", response.Message, response.GroupID, timestamp)
	case "dismiss":
		if response.ItemID != "" {
			fmt.Fprintf(output, "dismiss item=%s group=%s at=%s\n", response.ItemID, response.GroupID, timestamp)
		} else {
			fmt.Fprintf(output, "dismiss request=%s group=%s at=%s\n", response.RequestID, response.GroupID, timestamp)
		}
	case "response":
		fmt.Fprintf(output, "response request=%s option=%s group=%s at=%s\n", response.RequestID, response.OptionID, response.GroupID, timestamp)
	}
}
