package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/patrickmn/go-cache"
)

type Resolver struct {
	remoteUDPResolver *net.Resolver
	remoteTCPResolver *net.Resolver
	secondaryResolver *net.Resolver
	ttl               uint64
	domainIndex       *domainResourceIndex
	dnsResource       map[string][]net.IP
	dnsResourceCursor sync.Map
	useRemoteDNS      bool
	externalLookup    func(context.Context, string) ([]net.IP, error)
	additionalLookups []candidateLookup
	historyLookup     func(string) []net.IP
	successRecorder   func(string, net.IP)
	preferredIP       func(net.IP) bool

	dnsCache *cache.Cache

	IPPool *ippool.IPPool[[]client.DomainResource]

	timer  *time.Timer
	useTCP bool
	// check to use tcp resolver or udp resolver
	tcpLock           sync.RWMutex
	resolutionMu      sync.Mutex
	resolutions       map[string]*sharedResolution
	resolutionClosed  bool
	activeResolutions atomic.Int64

	closeOnce sync.Once
}

const remoteDNSTCPFallbackDelay = 300 * time.Millisecond
const candidatePreferenceWindow = 750 * time.Millisecond
const candidateLookupTimeout = 4 * time.Second

type lookupIPFunc func(context.Context, string, string) ([]net.IP, error)

type dnsLookupResult struct {
	ips []net.IP
	err error
}

type candidateLookupResult struct {
	source string
	ips    []net.IP
	err    error
}

type candidateLookup struct {
	source string
	lookup func(context.Context, string) ([]net.IP, error)
}

type sharedResolution struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	waiters int
	ip      net.IP
	err     error
}

func (r *Resolver) coordinationEntryCount() int {
	return int(r.activeResolutions.Load())
}

type contextKey string

var (
	ContextKeyFakeIP          = contextKey("FAKE_IP")
	ContextKeyResolveHost     = contextKey("RESOLVE_HOST")
	ContextKeyDomainResource  = contextKey("DOMAIN_RESOURCE")
	ContextKeyIPResource      = contextKey("IP_RESOURCE")
	ContextKeyFlowID          = contextKey("FLOW_ID")
	contextKeyIgnoreTCPPrefL3 = contextKey("IGNORE_TCP_PREF_L3")
)

var nextFlowID atomic.Uint64

func EnsureFlowID(ctx context.Context) (context.Context, uint64) {
	if existing, ok := ctx.Value(ContextKeyFlowID).(uint64); ok && existing != 0 {
		return ctx, existing
	}
	id := nextFlowID.Add(1)
	return context.WithValue(ctx, ContextKeyFlowID, id), id
}

func WithIgnoreTCPPrefL3(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKeyIgnoreTCPPrefL3, true)
}

func IgnoreTCPPrefL3(ctx context.Context) bool {
	ignore, _ := ctx.Value(contextKeyIgnoreTCPPrefL3).(bool)
	return ignore
}

func TCPPrefersL3(ctx context.Context) bool {
	if resource, ok := ctx.Value(ContextKeyDomainResource).(client.DomainResource); ok {
		return resource.EnableTCPPrefL3
	}
	if resource, ok := ctx.Value(ContextKeyIPResource).(client.IPResource); ok {
		return resource.EnableTCPPrefL3
	}
	return false
}

// Resolve ip address. If the host could be visited via VPN, this function set a DOMAIN_RESOURCE value in context. If resolve success, this function set a RESOLVE_HOST value in context.
func (r *Resolver) Resolve(ctx context.Context, host string) (resCtx context.Context, resIP net.IP, resErr error) {
	ctx, flowID := EnsureFlowID(ctx)
	host = normalizeHostname(host)
	log.Printf("flow=%d dns query host=%s remote=%t", flowID, host, r.useRemoteDNS)
	defer func() {
		if resErr == nil {
			resCtx = context.WithValue(resCtx, ContextKeyResolveHost, host)
		}
	}()
	var domainResourceFound = false
	var domainResources []client.DomainResource
	if domain, resources, found := matchDomainResource(r.domainIndex, host); found {
		domainResourceFound = true
		domainResources = resources
		ctx = context.WithValue(ctx, ContextKeyDomainResource, resources)
		log.Printf("flow=%d domain-resource matched=%s rules=%d", flowID, domain, len(resources))
	}

	if cachedIP, found := r.getDNSCache(host); found {
		log.Printf("flow=%d dns cache host=%s answer=%s", flowID, host, cachedIP.String())
		return ctx, cachedIP, nil
	}

	if r.dnsResource != nil {
		if ips, found := r.dnsResource[host]; found && len(ips) > 0 {
			cursorValue, _ := r.dnsResourceCursor.LoadOrStore(host, &atomic.Uint64{})
			cursor := cursorValue.(*atomic.Uint64)
			ip := ips[(cursor.Add(1)-1)%uint64(len(ips))]
			log.Printf("flow=%d dns policy host=%s answer=%s", flowID, host, ip.String())
			if domainResourceFound {
				err := r.IPPool.SetIPDomain(ip, host, domainResources)
				if err != nil {
					log.DebugPrintf("Set IP err: %s", err)
				}
			}
			return ctx, ip, nil
		}

		if fakeIPValue := ctx.Value(ContextKeyFakeIP); fakeIPValue != nil {
			if domainResourceFound {
				ip := r.IPPool.GenerateIP(host, domainResources)
				log.Printf("flow=%d dns fake-ip host=%s answer=%s", flowID, host, ip.String())
				return ctx, ip, nil
			}
		}
	}

	candidates := make([]net.IP, 0, 4)
	if r.historyLookup != nil {
		history := r.historyLookup(host)
		for _, ip := range history {
			candidates = appendUniqueIPs(candidates, ip)
		}
		if len(history) > 0 {
			log.Printf("flow=%d dns history host=%s answers=%v", flowID, host, history)
			if r.preferredIP != nil {
				for _, candidate := range history {
					if r.preferredIP(candidate) {
						r.setDNSCache(host, candidate)
						log.Printf("flow=%d dns selected resource-matching history host=%s answer=%s", flowID, host, candidate)
						return ctx, candidate, nil
					}
				}
			}
		}
	}
	results := make(chan candidateLookupResult, 3+len(r.additionalLookups))
	pending := 0
	if r.useRemoteDNS {
		pending++
		go func() {
			lookupCtx, cancel := context.WithTimeout(ctx, candidateLookupTimeout)
			defer cancel()
			ip, err := r.resolveCoordinated(lookupCtx, host, func(lookupCtx context.Context) (net.IP, error) {
				return r.resolveRemote(lookupCtx, host)
			})
			var ips []net.IP
			if ip != nil {
				ips = []net.IP{ip}
			}
			results <- candidateLookupResult{source: "remote", ips: ips, err: err}
		}()
	}
	if r.externalLookup != nil {
		pending++
		go func() {
			lookupCtx, cancel := context.WithTimeout(ctx, candidateLookupTimeout)
			defer cancel()
			ips, err := r.externalLookup(lookupCtx, host)
			results <- candidateLookupResult{source: "system", ips: ips, err: err}
		}()
	}
	if r.secondaryResolver != nil {
		pending++
		go func() {
			lookupCtx, cancel := context.WithTimeout(ctx, candidateLookupTimeout)
			defer cancel()
			ips, err := r.secondaryResolver.LookupIP(lookupCtx, "ip4", host)
			results <- candidateLookupResult{source: "secondary", ips: ips, err: err}
		}()
	}
	for _, extra := range r.additionalLookups {
		extra := extra
		pending++
		go func() {
			lookupCtx, cancel := context.WithTimeout(ctx, candidateLookupTimeout)
			defer cancel()
			ips, err := extra.lookup(lookupCtx, host)
			results <- candidateLookupResult{source: extra.source, ips: ips, err: err}
		}()
	}
	timer := time.NewTimer(candidatePreferenceWindow)
	defer timer.Stop()
	timerC := timer.C
	completed := 0
	for completed < pending {
		select {
		case result := <-results:
			completed++
			if result.err != nil {
				log.Printf("flow=%d %s DNS failed host=%s error=%v", flowID, result.source, host, result.err)
				continue
			}
			for _, ip := range result.ips {
				candidates = appendUniqueIPs(candidates, ip)
				if r.preferredIP != nil && r.preferredIP(ip) {
					r.setDNSCache(host, ip)
					log.Printf("flow=%d dns selected resource-matching %s answer host=%s answer=%s", flowID, result.source, host, ip)
					return ctx, ip, nil
				}
			}
			log.Printf("flow=%d dns %s host=%s answers=%v", flowID, result.source, host, result.ips)
		case <-timerC:
			timerC = nil
			if len(candidates) > 0 {
				completed = pending
			}
		case <-ctx.Done():
			return ctx, nil, ctx.Err()
		}
	}
	if len(candidates) == 0 {
		if ctx.Err() != nil {
			return ctx, nil, ctx.Err()
		}
		return ctx, nil, fmt.Errorf("all DNS sources failed for %s", host)
	}
	selected := candidates[0]
	if r.preferredIP != nil {
		for _, candidate := range candidates {
			if r.preferredIP(candidate) {
				selected = candidate
				log.Printf("flow=%d dns selected resource-matching IP host=%s answer=%s", flowID, host, selected)
				break
			}
		}
	}
	r.setDNSCache(host, selected)
	return ctx, selected, nil
}

func appendUniqueIPs(values []net.IP, candidate net.IP) []net.IP {
	if candidate == nil {
		return values
	}
	for _, value := range values {
		if value.Equal(candidate) {
			return values
		}
	}
	return append(values, candidate)
}

func (r *Resolver) SetExternalLookup(lookup func(context.Context, string) ([]net.IP, error)) {
	r.externalLookup = lookup
}

func (r *Resolver) AddLookupSource(source string, lookup func(context.Context, string) ([]net.IP, error)) {
	if source == "" || lookup == nil {
		return
	}
	r.additionalLookups = append(r.additionalLookups, candidateLookup{source: source, lookup: lookup})
}

func (r *Resolver) SetPreferredIP(match func(net.IP) bool) {
	r.preferredIP = match
}

func (r *Resolver) SetHistoryLookup(lookup func(string) []net.IP) {
	r.historyLookup = lookup
}

func (r *Resolver) SetSuccessRecorder(record func(string, net.IP)) {
	r.successRecorder = record
}

func (r *Resolver) RecordSuccessfulAddress(host string, ip net.IP) {
	if r.successRecorder == nil || host == "" || ip == nil {
		return
	}
	r.successRecorder(normalizeHostname(host), ip)
}

func (r *Resolver) resolveCoordinated(ctx context.Context, host string, lookup func(context.Context) (net.IP, error)) (net.IP, error) {
	r.resolutionMu.Lock()
	if r.resolutionClosed {
		r.resolutionMu.Unlock()
		return nil, net.ErrClosed
	}
	call := r.resolutions[host]
	if call == nil {
		lookupCtx, cancel := context.WithCancel(context.Background())
		call = &sharedResolution{ctx: lookupCtx, cancel: cancel, done: make(chan struct{})}
		if r.resolutions == nil {
			r.resolutions = make(map[string]*sharedResolution)
		}
		r.resolutions[host] = call
		r.activeResolutions.Add(1)
		go r.runResolution(host, call, lookup)
	}
	call.waiters++
	r.resolutionMu.Unlock()

	select {
	case <-ctx.Done():
		r.releaseResolutionWaiter(host, call)
		return nil, ctx.Err()
	case <-call.done:
		return call.ip, call.err
	}
}

func (r *Resolver) runResolution(host string, call *sharedResolution, lookup func(context.Context) (net.IP, error)) {
	call.ip, call.err = lookup(call.ctx)
	r.resolutionMu.Lock()
	if r.resolutions[host] == call {
		delete(r.resolutions, host)
	}
	r.resolutionMu.Unlock()
	call.cancel()
	r.activeResolutions.Add(-1)
	close(call.done)
}

func (r *Resolver) releaseResolutionWaiter(host string, call *sharedResolution) {
	r.resolutionMu.Lock()
	if r.resolutions[host] == call {
		call.waiters--
		if call.waiters == 0 {
			delete(r.resolutions, host)
			call.cancel()
		}
	}
	r.resolutionMu.Unlock()
}

func matchDomainResource(index *domainResourceIndex, host string) (string, []client.DomainResource, bool) {
	return index.Match(host)
}

func (r *Resolver) resolveRemote(ctx context.Context, host string) (net.IP, error) {
	r.tcpLock.RLock()
	useTCP := r.useTCP
	r.tcpLock.RUnlock()

	if useTCP {
		ips, err := r.remoteTCPResolver.LookupIP(ctx, "ip4", host)
		return r.cacheFirstIP(host, ips, err)
	}

	ips, udpFailed, err := lookupIPWithTCPFallback(
		ctx,
		host,
		r.remoteUDPResolver.LookupIP,
		r.remoteTCPResolver.LookupIP,
		remoteDNSTCPFallbackDelay,
	)
	if err != nil {
		return nil, err
	}
	if udpFailed {
		r.preferTCPTemporarily()
	}
	return r.cacheFirstIP(host, ips, nil)
}

func lookupIPWithTCPFallback(ctx context.Context, host string, udpLookup, tcpLookup lookupIPFunc, fallbackDelay time.Duration) ([]net.IP, bool, error) {
	lookupCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	udpResult := make(chan dnsLookupResult, 1)
	go func() {
		ips, err := udpLookup(lookupCtx, "ip4", host)
		udpResult <- dnsLookupResult{ips: ips, err: err}
	}()

	timer := time.NewTimer(fallbackDelay)
	defer timer.Stop()
	var tcpResult chan dnsLookupResult
	var udpErr, tcpErr error
	udpDone := false
	tcpDone := false

	startTCP := func() {
		if tcpResult != nil {
			return
		}
		tcpResult = make(chan dnsLookupResult, 1)
		go func() {
			ips, err := tcpLookup(lookupCtx, "ip4", host)
			tcpResult <- dnsLookupResult{ips: ips, err: err}
		}()
	}

	for {
		select {
		case result := <-udpResult:
			udpDone = true
			if result.err == nil {
				return result.ips, false, nil
			}
			udpErr = result.err
			startTCP()
			if tcpDone {
				return nil, true, errors.Join(udpErr, tcpErr)
			}
		case result := <-tcpResult:
			tcpDone = true
			if result.err == nil {
				return result.ips, udpDone, nil
			}
			tcpErr = result.err
			if udpDone {
				return nil, true, errors.Join(udpErr, tcpErr)
			}
		case <-timer.C:
			startTCP()
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func (r *Resolver) preferTCPTemporarily() {
	r.tcpLock.Lock()
	defer r.tcpLock.Unlock()
	r.useTCP = true
	if r.timer == nil {
		r.timer = time.AfterFunc(10*time.Minute, func() {
			r.tcpLock.Lock()
			r.useTCP = false
			r.timer = nil
			r.tcpLock.Unlock()
		})
	}
}

func (r *Resolver) cacheFirstIP(host string, ips []net.IP, err error) (net.IP, error) {
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("DNS lookup returned no addresses")
	}
	r.setDNSCache(host, ips[0])
	return ips[0], nil
}

func normalizeHostname(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

func (r *Resolver) RemoteUDPResolver() (*net.Resolver, error) {
	if r.remoteUDPResolver != nil {
		return r.remoteUDPResolver, nil
	} else {
		return nil, errors.New("remote UDP resolver is nil")
	}
}

func (r *Resolver) RemoteTCPResolver() (*net.Resolver, error) {
	if r.remoteTCPResolver != nil {
		return r.remoteTCPResolver, nil
	} else {
		return nil, errors.New("remote TCP resolver is nil")
	}
}

func (r *Resolver) ResolveWithSecondaryDNS(ctx context.Context, host string) (context.Context, net.IP, error) {
	if targets, err := r.secondaryResolver.LookupIP(ctx, "ip4", host); err != nil {
		log.Printf("Resolve IPv4 addr failed using secondary DNS: %s. Try IPv6 addr", host)

		if targets, err = r.secondaryResolver.LookupIP(ctx, "ip6", host); err != nil {
			log.Printf("Resolve IPv6 addr failed using secondary DNS: %s", host)
			return ctx, nil, err
		} else {
			log.Printf("%s -> %s", host, targets[0].String())
			return ctx, targets[0], nil
		}
	} else {
		log.Printf("%s -> %s", host, targets[0].String())
		return ctx, targets[0], nil
	}
}

func (r *Resolver) Close() {
	r.closeOnce.Do(func() {
		r.resolutionMu.Lock()
		r.resolutionClosed = true
		for host, call := range r.resolutions {
			delete(r.resolutions, host)
			call.cancel()
		}
		r.resolutionMu.Unlock()
		r.tcpLock.Lock()
		if r.timer != nil {
			r.timer.Stop()
			r.timer = nil
		}
		r.tcpLock.Unlock()
	})
}

func NewResolver(stack stack.Stack, remoteDNSServer, secondaryDNSServer string, ttl uint64, domainResources client.DomainResources, dnsResource map[string][]net.IP, useRemoteDNS bool) *Resolver {
	//domainSuffixTree := domainsuffixtrie.NewDomainSuffixTrie[bool]()
	//for domain := range domainResource {
	//	_ = domainSuffixTree.AddDomainSuffix(domain, true)
	//}

	resolver := &Resolver{
		remoteUDPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialUDP(ctx, &net.UDPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		remoteTCPResolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return stack.DialTCP(ctx, &net.TCPAddr{
					IP:   net.ParseIP(remoteDNSServer),
					Port: 53,
				})
			},
		},
		ttl:          ttl,
		domainIndex:  newDomainResourceIndex(domainResources),
		dnsResource:  dnsResource,
		dnsCache:     cache.New(time.Duration(ttl)*time.Second, time.Duration(ttl)*2*time.Second),
		useRemoteDNS: useRemoteDNS,
	}

	if secondaryDNSServer != "" {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(secondaryDNSServer, "53"))
			},
		}
	} else {
		resolver.secondaryResolver = &net.Resolver{
			PreferGo: true,
		}
	}
	var err error
	resolver.IPPool, err = ippool.NewIPPool[[]client.DomainResource]("198.18.0.0/16")
	if err != nil {
		log.Fatalf("Create Fake IP Pool failed: %v", err)
	}

	return resolver
}
