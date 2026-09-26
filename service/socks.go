package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/things-go/go-socks5"
)

func newSocks5Server(dialer *dial.Dialer, resolver *resolve.Resolver, user string, password string) *socks5.Server {
	var authMethods []socks5.Authenticator
	if user != "" && password != "" {
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{user: password},
		})
		log.Println("Neither traffic nor credentials are encrypted in the SOCKS5 protocol!")
	} else {
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}
	return socks5.NewServer(
		socks5.WithAuthMethods(authMethods),
		socks5.WithResolver(resolver),
		socks5.WithDial(dialer.DialIPPort),
		socks5.WithLogger(socks5.NewLogger(log.NewLogger("[SOCKS5] "))),
	)
}

// StartSocks5 starts a reusable SOCKS5 listener and returns ownership to the
// caller. Mobile clients use this instead of the process-global terminal hooks.
func StartSocks5(bindAddr string, dialer *dial.Dialer, resolver *resolve.Resolver, user string, password string) (io.Closer, error) {
	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, err
	}
	server := newSocks5Server(dialer, resolver, user, password)
	log.Printf("SOCKS5 server listening on %s", listener.Addr())
	log.Go("socks5_server", func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
			log.Println("SOCKS5 listen failed: " + serveErr.Error())
		}
	})
	return listener, nil
}

func ServeSocks5(bindAddr string, dialer *dial.Dialer, resolver *resolve.Resolver, user string, password string) {
	server := newSocks5Server(dialer, resolver, user, password)

	log.Printf("SOCKS5 server listening on %s", bindAddr)

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		panic("SOCKS5 listen failed: " + err.Error())
	}

	hook_func.RegisterTerminalFunc("CloseSocks5Listener", func(ctx context.Context) error {
		log.Println("Closing SOCKS5 listener...")
		if err := listener.Close(); err != nil {
			return fmt.Errorf("close SOCKS5 listener failed: %w", err)
		}
		return nil
	})

	if err = server.Serve(listener); err != nil {
		if errors.Is(err, net.ErrClosed) {
			log.Println("SOCKS5 server closed")
		} else {
			log.Println("SOCKS5 listen failed: " + err.Error())
		}
	}
}
