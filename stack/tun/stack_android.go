package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/log"
	"golang.org/x/net/ipv4"
)

const MTU uint32 = 1400
const maxInboundPacketSize = 1500

type Stack struct {
	endpoint *Endpoint
	l3Conn   io.ReadWriteCloser
	closed   atomic.Bool
}

func (s *Stack) Run() {
	if err := s.RunWithError(); err != nil {
		log.Printf("Android TUN stack stopped: %v", err)
	}
}

func (s *Stack) RunWithError() error {
	var connErr error
	s.l3Conn, connErr = s.endpoint.client.NewL3Conn()
	if connErr != nil {
		return fmt.Errorf("create L3 connection: %w", connErr)
	}
	errCh := make(chan error, 2)
	// Read from VPN server and send to TUN stack
	go func() {
		buf := make([]byte, maxInboundPacketSize)
		for {
			n, err := s.l3Conn.Read(buf)
			if err != nil {
				errCh <- fmt.Errorf("read VPN server: %w", err)
				return
			}
			log.DebugPrintf("Recv: read %d bytes", n)
			log.DebugDumpHex(buf[:n])

			err = s.endpoint.Write(buf[:n])
			if err != nil {
				errCh <- fmt.Errorf("write TUN: %w", err)
				return
			}
		}
	}()

	// Read from TUN stack and send to VPN server
	go func() {
		buf := make([]byte, MTU)
		for {
			n, err := s.endpoint.Read(buf)
			if err != nil {
				errCh <- fmt.Errorf("read TUN: %w", err)
				return
			}

			header, err := ipv4.ParseHeader(buf[:n])
			if err != nil {
				continue
			}

			// Filter out non-TCP/UDP packets otherwise error may occur
			if header.Protocol != syscall.IPPROTO_TCP && header.Protocol != syscall.IPPROTO_UDP {
				continue
			}

			n, err = s.l3Conn.Write(buf[:n])
			if err != nil {
				if errors.Is(err, client.ErrResourceNotFound) {
					log.Printf("Android TUN dropped unsupported destination without stopping VPN: %v", err)
					continue
				}
				errCh <- fmt.Errorf("write VPN server: %w", err)
				return
			}
			log.DebugPrintf("Send: wrote %d bytes", n)
			log.DebugDumpHex(buf[:n])
		}
	}()

	err := <-errCh
	intentionalClose := s.closed.Load()
	s.Close()
	if intentionalClose || errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}

// Close releases both ends owned by the Android stack. The TUN descriptor is
// transferred to Go by the caller and must have exactly one owner.
func (s *Stack) Close() {
	if s.closed.Swap(true) {
		return
	}
	if s.endpoint != nil && s.endpoint.readWriteCloser != nil {
		_ = s.endpoint.readWriteCloser.Close()
	}
	if s.l3Conn != nil {
		_ = s.l3Conn.Close()
	}
}

type Endpoint struct {
	client client.Client

	readWriteCloser io.ReadWriteCloser
	ip              net.IP

	tcpDialer *net.Dialer
	udpDialer *net.Dialer
	configMu  sync.RWMutex
}

func (ep *Endpoint) Write(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	_, err := ep.readWriteCloser.Write(buf)
	return err
}

func (ep *Endpoint) Read(buf []byte) (int, error) {
	return ep.readWriteCloser.Read(buf)
}

func (s *Stack) AddRoute(target string) error {
	return nil
}

func (s *Stack) SetupResolve(zcdns.LocalServer) {}

func (s *Stack) SetupIPPool(*ippool.IPPool[[]client.DomainResource]) {}

func NewStack(client client.Client, _ bool, _ bool, _ []client.IPResource) (*Stack, error) {
	s := &Stack{}

	s.endpoint = &Endpoint{
		client: client,
	}

	var err error
	s.endpoint.ip, err = client.IP()
	if err != nil {
		return nil, err
	}

	// We need this dialer to bind to device otherwise packets will not be sent via TUN
	s.endpoint.tcpDialer = &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
	}

	s.endpoint.udpDialer = &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   s.endpoint.ip,
			Port: 0,
		},
	}

	return s, nil
}

func (s *Stack) SetupTun(fd int) {
	s.endpoint.readWriteCloser = os.NewFile(uintptr(fd), "tun")
}
