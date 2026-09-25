//go:build android

package mobiletun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	tun2socks "github.com/sagernet/go-tun2socks/core"
	M "github.com/sagernet/sing/common/metadata"
)

type Stack struct {
	file      *os.File
	lwip      tun2socks.LWIPStack
	dialer    *dial.Dialer
	resolver  *resolve.Resolver
	dnsServer zcdns.LocalServer
	closed    atomic.Bool
	closeOnce sync.Once
	dnsHosts  sync.Map
}

func New(fd int, dialer *dial.Dialer, resolver *resolve.Resolver, dnsServer zcdns.LocalServer) (*Stack, error) {
	if fd < 0 || dialer == nil || resolver == nil || dnsServer == nil {
		return nil, fmt.Errorf("invalid mobile TUN dependencies")
	}
	s := &Stack{
		file:      os.NewFile(uintptr(fd), "android-tun"),
		dialer:    dialer,
		resolver:  resolver,
		dnsServer: dnsServer,
	}
	tun2socks.RegisterTCPConnHandler(tcpHandler{stack: s})
	tun2socks.RegisterUDPConnHandler(udpHandler{stack: s})
	tun2socks.RegisterOutputFn(func(packet []byte) (int, error) {
		if s.closed.Load() {
			return 0, net.ErrClosed
		}
		return s.file.Write(packet)
	})
	s.lwip = tun2socks.NewLWIPStack()
	return s, nil
}

func (s *Stack) Run() error {
	buffer := make([]byte, 65535)
	for {
		n, err := s.file.Read(buffer)
		if err != nil {
			if s.closed.Load() || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read Android TUN: %w", err)
		}
		if n == 0 {
			continue
		}
		if _, err = s.lwip.Write(buffer[:n]); err != nil && !s.closed.Load() {
			log.Printf("tun2socks input dropped: %v", err)
		}
	}
}

func (s *Stack) Close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		if s.file != nil {
			_ = s.file.Close()
		}
		if s.lwip != nil {
			_ = s.lwip.Close()
		}
	})
}

type tcpHandler struct{ stack *Stack }

func (h tcpHandler) Handle(downstream net.Conn) error {
	target := downstream.RemoteAddr().String()
	ctx := context.Background()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip != nil && h.stack.resolver.IPPool != nil {
		if domain, resources, found := h.stack.resolver.IPPool.GetDomain(ip); found {
			ctx = context.WithValue(ctx, resolve.ContextKeyResolveHost, domain)
			ctx = context.WithValue(ctx, resolve.ContextKeyDomainResource, resources)
			log.Printf("tun2socks restored fakeip=%s domain=%s", ip, domain)
		} else if domain, found := h.stack.dnsHosts.Load(ip.String()); found {
			ctx = context.WithValue(ctx, resolve.ContextKeyResolveHost, domain.(string))
			log.Printf("tun2socks restored DNS host ip=%s domain=%s", ip, domain)
		}
	}
	upstream, err := h.stack.dialer.DialIPPort(ctx, "tcp", target)
	if err != nil {
		return err
	}
	go relayTCP(downstream, upstream)
	return nil
}

func relayTCP(left, right net.Conn) {
	defer left.Close()
	defer right.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(left, right); done <- struct{}{} }()
	go func() { _, _ = io.Copy(right, left); done <- struct{}{} }()
	<-done
}

type udpHandler struct{ stack *Stack }

func (h udpHandler) ReceiveTo(conn tun2socks.UDPConn, payload []byte, target M.Socksaddr) error {
	if target.Port != 53 {
		log.Printf("tun2socks UDP dropped: target=%s (only DNS is supported)", target)
		return nil
	}
	request := new(dns.Msg)
	if err := request.Unpack(payload); err != nil {
		return err
	}
	ctx := context.WithValue(context.Background(), resolve.ContextKeyFakeIP, true)
	response, err := h.stack.dnsServer.HandleDnsMsg(ctx, request)
	if err != nil {
		return err
	}
	queryHost := ""
	if len(request.Question) > 0 {
		queryHost = strings.TrimSuffix(request.Question[0].Name, ".")
	}
	for _, answer := range response.Answer {
		if record, ok := answer.(*dns.A); ok {
			host := queryHost
			if host == "" {
				host = strings.TrimSuffix(record.Hdr.Name, ".")
			}
			h.stack.dnsHosts.Store(record.A.String(), host)
			log.Printf("tun2socks learned DNS context host=%s ip=%s", host, record.A)
		}
	}
	packed, err := response.Pack()
	if err != nil {
		return err
	}
	_, err = conn.WriteFrom(packed, target)
	return err
}
