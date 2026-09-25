package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

const (
	keepAliveRequestTimeout    = 10 * time.Second
	keepAliveDNSAttemptTimeout = 3 * time.Second
	keepAliveDrainLimit        = 32 << 10
)

func KeepAlive(ctx context.Context, resolver *resolve.Resolver, dialer *dial.Dialer, keepAliveURL string) {
	KeepAliveWithStatus(ctx, resolver, dialer, keepAliveURL, nil)
}

func KeepAliveWithStatus(ctx context.Context, resolver *resolve.Resolver, dialer *dial.Dialer, keepAliveURL string, report func(bool, time.Duration, string)) {
	if keepAliveURL != "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = dialer.Dial
		transport.ResponseHeaderTimeout = keepAliveRequestTimeout
		client := &http.Client{
			Transport: transport,
		}
		defer client.CloseIdleConnections()

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		runHTTPKeepAliveWithStatus(ctx, client, keepAliveURL, ticker.C, report)
		return
	} else {
		remoteUDPResolver, err := resolver.RemoteUDPResolver()
		if err != nil {
			log.Printf("KeepAlive: %s", err)
		}

		remoteTCPResolver, err := resolver.RemoteTCPResolver()
		if err != nil {
			log.Printf("KeepAlive: %s", err)
		}

		if remoteUDPResolver == nil && remoteTCPResolver == nil {
			log.Printf("KeepAlive: No remote resolver available")
			return
		}

		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			started := time.Now()
			success := false
			if remoteUDPResolver != nil {
				requestCtx, cancel := context.WithTimeout(ctx, keepAliveDNSAttemptTimeout)
				_, err := remoteUDPResolver.LookupIP(requestCtx, "ip4", "www.baidu.com")
				cancel()
				if err != nil {
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						log.DebugPrintf("KeepAlive using UDP error: %s", err)
					}
				} else {
					success = true
					log.Printf("KeepAlive using UDP: OK")
					if report != nil {
						report(true, time.Since(started), "DNS UDP")
					}
				}
			}

			if !success && remoteTCPResolver != nil {
				requestCtx, cancel := context.WithTimeout(ctx, keepAliveDNSAttemptTimeout)
				_, err := remoteTCPResolver.LookupIP(requestCtx, "ip4", "www.baidu.com")
				cancel()
				if err != nil {
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						log.Printf("KeepAlive using TCP error: %s", err)
					}
				} else {
					success = true
					log.Printf("KeepAlive using TCP: OK")
					if report != nil {
						report(true, time.Since(started), "DNS TCP")
					}
				}
			}
			if !success {
				requestCtx, cancel := context.WithTimeout(ctx, keepAliveDNSAttemptTimeout)
				source, err := resolver.ProbeFallback(requestCtx, "www.baidu.com")
				cancel()
				if err == nil {
					success = true
					log.Printf("KeepAlive using %s: OK", source)
					if report != nil {
						report(true, time.Since(started), source)
					}
				} else if report != nil {
					report(false, time.Since(started), err.Error())
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}

func runHTTPKeepAlive(ctx context.Context, client *http.Client, keepAliveURL string, ticks <-chan time.Time) {
	runHTTPKeepAliveWithStatus(ctx, client, keepAliveURL, ticks, nil)
}

func runHTTPKeepAliveWithStatus(ctx context.Context, client *http.Client, keepAliveURL string, ticks <-chan time.Time, report func(bool, time.Duration, string)) {
	for {
		started := time.Now()
		requestCtx, cancel := context.WithTimeout(ctx, keepAliveRequestTimeout)
		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, keepAliveURL, nil)
		if err != nil {
			log.Printf("KeepAlive: %s", err)
			if report != nil {
				report(false, time.Since(started), err.Error())
			}
		} else {
			resp, err := client.Do(req)
			if err != nil {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					log.Printf("KeepAlive: %s", err)
				}
				if report != nil {
					report(false, time.Since(started), err.Error())
				}
			} else {
				log.Printf("KeepAlive: OK, status code %d", resp.StatusCode)
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, keepAliveDrainLimit+1))
				_ = resp.Body.Close()
				if report != nil {
					report(true, time.Since(started), fmt.Sprintf("HTTP %d", resp.StatusCode))
				}
			}
		}
		cancel()

		select {
		case <-ctx.Done():
			return
		case <-ticks:
		}
	}
}
