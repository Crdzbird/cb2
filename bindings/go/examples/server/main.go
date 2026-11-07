// Command server is an example HTTP service built on the cb2 Go binding.
//
// POST /login takes {"username","password"} and answers with a cb2.local
// access token whose cnf claim binds a fresh proof key, and with that
// proof key. GET /me accepts the token only together with a holder proof
// made with the proof key for this very request, and answers with the
// token's subject. A tampered, expired, replayed or misdirected request
// is refused with 401 and the library's verdict name.
//
// Usage:
//
//	server [-addr 127.0.0.1:8080] [-origin http://127.0.0.1:8080] [-ttl 15m] [-user alice:wonderland]
//
// The token key comes from the CB2_EXAMPLE_KEY environment variable (a
// kcb2.local string, see cb2cli keygen) or is generated at start, in
// which case tokens do not survive a restart.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	cb2 "github.com/Crdzbird/cb2/bindings/go"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("server stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	origin := flag.String("origin", "", "public origin clients call, the issuer and the base of every proof target (default http://<addr>)")
	ttl := flag.Duration("ttl", 15*time.Minute, "access token lifetime")
	user := flag.String("user", "alice:wonderland", "the demo account, name:password")
	flag.Parse()
	if *origin == "" {
		*origin = "http://" + *addr
	}
	name, password, ok := strings.Cut(*user, ":")
	if !ok || name == "" || password == "" {
		return fmt.Errorf("-user must be name:password")
	}

	key, err := loadKey()
	if err != nil {
		return err
	}
	defer key.Close()
	id, err := key.PaserkID()
	if err != nil {
		return err
	}

	svc := newService(key, *origin, *ttl, map[string]string{name: password}, time.Now, log)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           svc.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() {
		served <- srv.ListenAndServe()
	}()
	log.Info("listening", "addr", *addr, "origin", *origin, "ttl", ttl.String(), "key", id, "cb2", cb2.Version())

	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-served; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func loadKey() (*cb2.LocalKey, error) {
	text := os.Getenv("CB2_EXAMPLE_KEY")
	if text == "" {
		return cb2.GenerateLocalKey()
	}
	key, err := cb2.LocalKeyFromPaserk(text)
	if err != nil {
		return nil, fmt.Errorf("CB2_EXAMPLE_KEY: %w", err)
	}
	return key, nil
}
