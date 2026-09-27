package dial

import (
	"net"
	"strconv"
	"strings"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/stack"
)

import (
	"context"
	"errors"
)

// ErrACLDenied is returned by DialIPPort when the caller forced VPN routing
// (via alwaysUseVPN / proxy_all) for a destination that the sangfor server
// would not accept. Sending it through the L3 tunnel would cause the server
// to terminate the entire session with cmd 0x08 SHUTDOWN, killing all other
// in-flight connections. Refusing here mirrors what the official EasyConnect
// client does and keeps the tunnel alive.
var ErrACLDenied = errors.New("destination not in sangfor IPResources whitelist (would trigger tunnel SHUTDOWN)")

type Dialer struct {
	stack                stack.Stack
	resolver             *resolve.Resolver
	ipResources          []client.IPResource
	resourceIndex        *ipresource.Index
	alwaysUseVPN         bool
	dialDirectHTTPProxy  string // format: "ip:port"
	dialDirectSocksProxy string // WORKING IN PROCESS
}

// dialDirectIP need have a `hostAddr` parameter, which will be passed to PROXY. But `hostAddr` maybe empty, ipAddr never be empty.
func (d *Dialer) dialDirectIP(ctx context.Context, network, ipAddr string, hostAddr string) (net.Conn, error) {
	// only support http proxy now and tcp network type
	if d.dialDirectHTTPProxy != "" && network == "tcp" {
		usedAddr := ipAddr
		if hostAddr != "" {
			usedAddr = hostAddr
		}
		return d.dialDirectWithHTTPProxy(ctx, usedAddr)
		// only support tcp for socks proxy
	} else if d.dialDirectSocksProxy != "" && network == "tcp" {
		if hostAddr != "" {
			return d.dialDirectWithSocksProxy(ctx, network, hostAddr, false)
		} else {
			return d.dialDirectWithSocksProxy(ctx, network, ipAddr, true)
		}
	} else {
		return d.dialDirectWithoutProxy(ctx, network, ipAddr)
	}
}

func (d *Dialer) dialDirectHost(ctx context.Context, network, hostAddr string) (net.Conn, error) {
	// only support http proxy now and tcp network type
	if d.dialDirectHTTPProxy != "" && network == "tcp" {
		return d.dialDirectWithHTTPProxy(ctx, hostAddr)
		// only support tcp for socks proxy
	} else if d.dialDirectSocksProxy != "" && network == "tcp" {
		return d.dialDirectWithSocksProxy(ctx, network, hostAddr, false)
	} else {
		return d.dialDirectWithoutProxy(ctx, network, hostAddr)
	}
}

func (d *Dialer) DialIPPort(ctx context.Context, network, ipAddr string) (net.Conn, error) {
	ctx, flowID := resolve.EnsureFlowID(ctx)
	hostAddr := ""
	if _, hostAddrOK := ctx.Value(resolve.ContextKeyResolveHost).(string); hostAddrOK {
		// hostAddr doesn't have port field at now
		hostAddr = ctx.Value(resolve.ContextKeyResolveHost).(string)
	}
	parts := strings.Split(ipAddr, ":")
	if len(parts) >= 2 {
		// maybe need extra check for parts[len(parts)-1] is port or not?
		hostAddr += ":" + parts[len(parts)-1]
	}

	// If addr is IPv6, use direct connection
	if len(parts) > 2 {
		log.Printf("flow=%d decision=DIRECT reason=ipv6 target=%s network=%s", flowID, ipAddr, network)
		return d.dialDirectIP(ctx, network, ipAddr, hostAddr)
	}

	ip, portStr, err := net.SplitHostPort(ipAddr)
	if err != nil {
		return nil, errors.New("Invalid address: " + ipAddr)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New("Invalid port in address: " + ipAddr)
	}

	var useVPN = false
	var target *net.IPAddr

	if pureIp := net.ParseIP(ip); pureIp != nil {
		target = &net.IPAddr{IP: pureIp}
	} else {
		log.Printf("Illegal situation, host is not pure IP format: %s", ip)
		return d.dialDirectIP(ctx, network, ipAddr, hostAddr)
	}

	if d.alwaysUseVPN {
		useVPN = true
	}

	// Track whether dst:port matches any sangfor-issued resource. We always
	// run both resource lookups (even if useVPN was already forced true by
	// alwaysUseVPN) so we can enforce the server-side ACL client-side.
	matchedResource := false

	if res := ctx.Value(resolve.ContextKeyDomainResource); res != nil {
		var resource client.DomainResource
		var matched bool
		switch resources := res.(type) {
		case []client.DomainResource:
			resource, matched = matchDomainResourceForTunnel(resources, network, port)
		case client.DomainResource:
			resource, matched = matchDomainResourceForTunnel([]client.DomainResource{resources}, network, port)
		}
		if matched {
			ctx = context.WithValue(ctx, resolve.ContextKeyDomainResource, resource)
			useVPN = true
			matchedResource = true
			log.Printf(
				"flow=%d matched=DOMAIN appId=%s nodeGroup=%s tcpPrefL3=%t addrPretend=%t",
				flowID, resource.AppID, resource.NodeGroupID, resource.EnableTCPPrefL3, resource.AddrPretend,
			)
		}
	}

	if !matchedResource && d.ipResources != nil {
		if resource, matched := matchIPResourceForTunnel(d.resourceIndex, target.IP, network, port); matched {
			ctx = context.WithValue(ctx, resolve.ContextKeyIPResource, resource)
			useVPN = true
			matchedResource = true
			log.Printf(
				"flow=%d matched=IP range=%s-%s appId=%s nodeGroup=%s tcpPrefL3=%t",
				flowID, resource.IPMin, resource.IPMax, resource.AppID, resource.NodeGroupID, resource.EnableTCPPrefL3,
			)
		}
	}

	// Client-side ACL enforcement: if alwaysUseVPN forced VPN routing for a
	// dst:port that isn't in the server-issued resource list, sending it
	// upstream causes sangfor to terminate the L3 tunnel (cmd 0x08 SHUTDOWN
	// on the next handshake). The official EasyConnect client filters here
	// via CSClient before traffic ever reaches the tunnel; we do the same.
	// Skipped when IPResources are unavailable (parse_resource=false), since
	// we have no whitelist to enforce. An empty but non-nil slice still means
	// resources were parsed and no IP destinations are allowed.
	if useVPN && !matchedResource && d.ipResources != nil {
		log.Printf("flow=%d decision=DENY reason=acl target=%s network=%s", flowID, ipAddr, network)
		return nil, ErrACLDenied
	}

	if useVPN {
		if network == "tcp" {
			log.Printf("flow=%d decision=VPN target=%s network=tcp host=%s", flowID, ipAddr, hostAddr)

			conn, dialErr := d.stack.DialTCP(ctx, &net.TCPAddr{
				IP:   target.IP,
				Port: port,
			})
			if dialErr == nil {
				if host, ok := ctx.Value(resolve.ContextKeyResolveHost).(string); ok {
					d.resolver.RecordSuccessfulAddress(host, target.IP)
					log.Printf("flow=%d learned successful mapping host=%s ip=%s", flowID, host, target.IP)
				}
			}
			return conn, dialErr
		} else if network == "udp" {
			log.Printf("flow=%d decision=VPN target=%s network=udp host=%s", flowID, ipAddr, hostAddr)

			return d.stack.DialUDP(ctx, &net.UDPAddr{
				IP:   target.IP,
				Port: port,
			})
		} else {
			log.Printf("VPN only support TCP/UDP. Connection to %s will use direct connection", ipAddr)
			return d.dialDirectIP(ctx, network, ipAddr, hostAddr)
		}
	} else {
		log.Printf("flow=%d decision=DIRECT target=%s network=%s host=%s", flowID, ipAddr, network, hostAddr)
		return d.dialDirectIP(ctx, network, ipAddr, hostAddr)
	}
}

func matchDomainResourceForTunnel(resources []client.DomainResource, network string, port int) (client.DomainResource, bool) {
	if network == "tcp" {
		if resource, ok := client.MatchDomainResourceWhere(resources, network, port, func(resource client.DomainResource) bool {
			return !resource.EnableTCPPrefL3
		}); ok {
			return resource, true
		}
	}
	return client.MatchDomainResource(resources, network, port)
}

func matchesIPResource(index *ipresource.Index, target net.IP, network string, port int) bool {
	_, ok := matchIPResourceForTunnel(index, target, network, port)
	return ok
}

func matchIPResourceForTunnel(index *ipresource.Index, target net.IP, network string, port int) (client.IPResource, bool) {
	if network == "tcp" {
		if resource, ok := index.MatchWhere(target, network, port, func(resource client.IPResource) bool {
			return !resource.EnableTCPPrefL3
		}); ok {
			return resource, true
		}
	}
	return index.Match(target, network, port)
}

func (d *Dialer) Dial(ctx context.Context, network string, addr string) (net.Conn, error) {
	ctx, flowID := resolve.EnsureFlowID(ctx)
	log.Printf("flow=%d start target=%s network=%s", flowID, addr, network)
	// If addr is IPv6, use direct connection
	if strings.Count(addr, ":") > 1 {
		return d.dialDirectIP(ctx, network, addr, "")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return d.dialDirectHost(ctx, network, addr)
	}

	var ip net.IP
	if ip = net.ParseIP(host); ip == nil {
		ctx, ip, err = d.resolver.Resolve(ctx, host)
		if err != nil {
			return d.dialDirectHost(ctx, network, addr)
		}

		if strings.Count(ip.String(), ":") > 0 {
			return d.dialDirectIP(ctx, network, ip.String()+":"+port, addr)
		}
	}

	return d.DialIPPort(ctx, network, ip.String()+":"+port)
}

func NewDialer(stack stack.Stack, resolver *resolve.Resolver, ipResources []client.IPResource, alwaysUseVPN bool, dialDirectProxy string) *Dialer {
	dialHttpProxy := ""
	dialSocksProxy := ""
	if strings.HasPrefix(dialDirectProxy, "http://") {
		dialHttpProxy = strings.TrimPrefix(dialDirectProxy, "http://")
	} else if strings.HasPrefix(dialDirectProxy, "socks://") {
		dialSocksProxy = strings.TrimPrefix(dialDirectProxy, "socks://")
	} else if len(dialDirectProxy) > 0 {
		log.Println("暂不支持除[http/socks]之外的DialDirectProxy，忽略该配置项")
	}
	return &Dialer{
		stack:                stack,
		resolver:             resolver,
		ipResources:          ipResources,
		resourceIndex:        ipresource.New(ipResources),
		alwaysUseVPN:         alwaysUseVPN,
		dialDirectHTTPProxy:  dialHttpProxy,
		dialDirectSocksProxy: dialSocksProxy,
	}
}
