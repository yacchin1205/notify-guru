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

	"notify.guru/internal/mcpserver"
	"notify.guru/internal/notify"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("notifyg", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	baseURL := flags.String("base-url", "https://notify.guru", "notify.guru service URL")
	title := flags.String("title", "Development session", "interactive session title")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return fmt.Errorf("usage: notifyg [--base-url URL] [--title TITLE] [mcp]")
	}

	api, err := notify.NewAPI(*baseURL)
	if err != nil {
		return err
	}
	store := notify.NewStore(api)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if flags.NArg() == 1 {
		if flags.Arg(0) != "mcp" {
			return fmt.Errorf("unknown mode %q", flags.Arg(0))
		}
		err := mcpserver.New(store).Run(ctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return interactive(ctx, store, *title, os.Stdin, os.Stdout, os.Stderr)
}

func interactive(ctx context.Context, store *notify.Store, title string, input io.Reader, output, errorOutput io.Writer) error {
	sessionID, pairingURL, err := store.Create(ctx, title)
	if err != nil {
		return err
	}
	qr, err := notify.QRCode(pairingURL)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Session: %s\n%s\n%s\n", sessionID, qr, pairingURL)
	fmt.Fprintln(output, "Commands: join, pair, notify TEXT, status TEXT, request PROMPT | OPTION | OPTION, responses, close, quit")

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 300_000)
	for {
		fmt.Fprint(output, "notifyg> ")
		if !scanner.Scan() {
			return scanner.Err()
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		command, argument, _ := strings.Cut(line, " ")
		switch command {
		case "join":
			count, err := store.RefreshGroups(ctx, sessionID)
			if err != nil {
				fmt.Fprintln(errorOutput, err)
				continue
			}
			fmt.Fprintf(output, "%d device group(s) joined\n", count)
		case "pair":
			url, err := store.AddPairing(ctx, sessionID)
			if err != nil {
				fmt.Fprintln(errorOutput, err)
				continue
			}
			qr, err := notify.QRCode(url)
			if err != nil {
				fmt.Fprintln(errorOutput, err)
				continue
			}
			fmt.Fprintf(output, "%s\n%s\n", qr, url)
		case "notify":
			if err := store.SendNotify(ctx, sessionID, argument); err != nil {
				fmt.Fprintln(errorOutput, err)
				continue
			}
			fmt.Fprintln(output, "sent")
		case "status":
			if err := store.SendStatus(ctx, sessionID, argument); err != nil {
				fmt.Fprintln(errorOutput, err)
				continue
			}
			fmt.Fprintln(output, "sent")
		case "request":
			parts := strings.Split(argument, "|")
			if len(parts) < 3 {
				fmt.Fprintln(errorOutput, "request requires a prompt and at least two options separated by |")
				continue
			}
			for index := range parts {
				parts[index] = strings.TrimSpace(parts[index])
			}
			requestID, choices, err := store.SendRequest(ctx, sessionID, parts[0], parts[1:])
			if err != nil {
				fmt.Fprintln(errorOutput, err)
				continue
			}
			fmt.Fprintf(output, "request %s sent: %v\n", requestID, choices)
		case "responses":
			responses, err := store.Responses(ctx, sessionID)
			if err != nil {
				fmt.Fprintln(errorOutput, err)
				continue
			}
			for _, response := range responses {
				fmt.Fprintf(output, "response request=%s option=%s group=%s at=%s\n", response.RequestID, response.OptionID, response.GroupID, response.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
			}
		case "close":
			if err := store.Close(ctx, sessionID); err != nil {
				fmt.Fprintln(errorOutput, err)
				continue
			}
			fmt.Fprintln(output, "closed")
			return nil
		case "quit":
			return nil
		default:
			fmt.Fprintf(errorOutput, "unknown command %q\n", command)
		}
	}
}
