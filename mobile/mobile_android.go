package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/client/authchallenge"
	easyconnectclient "github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tun"
	"github.com/mythologyli/zju-connect/underlay"
	"inet.af/netaddr"
)

// ChallengeCallback is implemented by the Android layer. OnChallenge receives
// a JSON challenge and blocks until the UI returns a JSON response.
type ChallengeCallback interface {
	OnChallenge(challengeJSON string) string
}

type LogCallback interface {
	OnLog(line string)
}

type DNSCallback interface {
	Resolve(host string) string
	LookupHistory(host string) string
	RecordSuccess(host string, address string)
}

type callbackLogWriter struct{ callback LogCallback }

func (w callbackLogWriter) Write(value []byte) (int, error) {
	if w.callback != nil {
		w.callback.OnLog(strings.TrimSpace(string(value)))
	}
	return len(value), nil
}

// SetLogCallback mirrors Go core logs into the Android host. Passing nil
// restores stdout logging.
func SetLogCallback(callback LogCallback) {
	if callback == nil {
		log.SetOutput(nil)
		return
	}
	log.SetOutput(callbackLogWriter{callback: callback})
}

type callbackChallengeHandler struct{ callback ChallengeCallback }

func (h callbackChallengeHandler) request(kind string, payload any, response any) error {
	request, err := json.Marshal(map[string]any{"type": kind, "payload": payload})
	if err != nil {
		return err
	}
	value := h.callback.OnChallenge(string(request))
	if value == "" {
		return fmt.Errorf("authentication challenge cancelled")
	}
	return json.Unmarshal([]byte(value), response)
}

func (h callbackChallengeHandler) HandleCodeChallenge(challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
	var response authchallenge.CodeResponse
	err := h.request("code", map[string]any{
		"kind": challenge.Kind, "message": challenge.Message,
		"canSkipSecondaryAuth": challenge.CanSkipSecondaryAuth,
	}, &response)
	return response, err
}

func (h callbackChallengeHandler) HandleTextCaptcha(challenge authchallenge.TextCaptchaChallenge) (authchallenge.TextCaptchaResponse, error) {
	var response authchallenge.TextCaptchaResponse
	err := h.request("textCaptcha", map[string]any{
		"imageBase64": base64.StdEncoding.EncodeToString(challenge.Image), "message": challenge.Message,
	}, &response)
	return response, err
}

func (h callbackChallengeHandler) HandleClickCaptcha(challenge authchallenge.ClickCaptchaChallenge) (authchallenge.ClickCaptchaResponse, error) {
	var response authchallenge.ClickCaptchaResponse
	err := h.request("clickCaptcha", map[string]any{
		"imageBase64": base64.StdEncoding.EncodeToString(challenge.Image), "message": challenge.Message,
	}, &response)
	return response, err
}

func (h callbackChallengeHandler) HandleExternalLogin(challenge authchallenge.ExternalLoginChallenge) (authchallenge.ExternalLoginResponse, error) {
	var response authchallenge.ExternalLoginResponse
	err := h.request("externalLogin", map[string]any{
		"kind": challenge.Kind, "loginUrl": challenge.LoginURL, "message": challenge.Message,
	}, &response)
	return response, err
}

type mobileConfig struct {
	Protocol                string            `json:"protocol"`
	Server                  string            `json:"server"`
	Port                    int               `json:"port"`
	Username                string            `json:"username"`
	Password                string            `json:"password"`
	TOTPSecret              string            `json:"totpSecret"`
	AuthType                string            `json:"authType"`
	LoginDomain             string            `json:"loginDomain"`
	Phone                   string            `json:"phone"`
	ClientData              string            `json:"clientData"`
	SocksBind               string            `json:"socksBind"`
	HTTPBind                string            `json:"httpBind"`
	RemoteDNS               string            `json:"remoteDns"`
	SecondaryDNS            string            `json:"secondaryDns"`
	ProxyAll                bool              `json:"proxyAll"`
	DisableConfig           bool              `json:"disableServerConfig"`
	DNSTTL                  int               `json:"dnsTtl"`
	UpdateBestNodesInterval int               `json:"updateBestNodesInterval"`
	SessionRefreshInterval  int               `json:"sessionRefreshInterval"`
	CustomDNS               map[string]string `json:"customDns"`
}

type mobileResult struct {
	OK              bool            `json:"ok"`
	ErrorCode       string          `json:"errorCode,omitempty"`
	ErrorMessage    string          `json:"errorMessage,omitempty"`
	Address         string          `json:"address,omitempty"`
	PrefixLength    int             `json:"prefixLength,omitempty"`
	MTU             int             `json:"mtu,omitempty"`
	Routes          []string        `json:"routes,omitempty"`
	DNSServers      []string        `json:"dnsServers,omitempty"`
	SocksAddress    string          `json:"socksAddress,omitempty"`
	HTTPAddress     string          `json:"httpAddress,omitempty"`
	ClientData      string          `json:"clientData,omitempty"`
	AuthMethods     []auth.AuthInfo `json:"authMethods,omitempty"`
	DomainResources []string        `json:"domainResources,omitempty"`
}

type mobileSession struct {
	client   client.Client
	underlay *underlay.Dialer
	gvisor   *gvisor.Stack
	resolver *resolve.Resolver
	servers  []io.Closer
	tunStack *tun.Stack
	mu       sync.Mutex
}

type snapshotIPResource struct {
	IPMin           string `json:"ipMin"`
	IPMax           string `json:"ipMax"`
	PortMin         int    `json:"portMin"`
	PortMax         int    `json:"portMax"`
	Protocol        string `json:"protocol"`
	AppID           string `json:"appId,omitempty"`
	NodeGroupID     string `json:"nodeGroupId,omitempty"`
	EnableTCPPrefL3 bool   `json:"enableTcpPrefL3"`
}

type snapshotDomainResource struct {
	Domain          string `json:"domain"`
	PortMin         int    `json:"portMin"`
	PortMax         int    `json:"portMax"`
	Protocol        string `json:"protocol"`
	AppID           string `json:"appId,omitempty"`
	NodeGroupID     string `json:"nodeGroupId,omitempty"`
	EnableTCPPrefL3 bool   `json:"enableTcpPrefL3"`
	AddrPretend     bool   `json:"addrPretend"`
}

type resourceSnapshot struct {
	VirtualIP       string                   `json:"virtualIp,omitempty"`
	DNSServers      []string                 `json:"dnsServers,omitempty"`
	IPResources     []snapshotIPResource     `json:"ipResources,omitempty"`
	DomainResources []snapshotDomainResource `json:"domainResources,omitempty"`
	DNSResources    map[string][]string      `json:"dnsResources,omitempty"`
}

var sessionMu sync.Mutex
var activeSession *mobileSession
var dnsCallback DNSCallback

func SetDNSCallback(callback DNSCallback) {
	sessionMu.Lock()
	dnsCallback = callback
	sessionMu.Unlock()
}

// Capabilities reports only features implemented by this mobile binding.
func Capabilities() string {
	return `{"apiVersion":2,"easyConnectVpn":true,"aTrustVpn":true,"localSocks5":true,"localHttp":true,"interactiveAuth":true,"clickCaptcha":false}`
}

// FetchAuthMethods asks an aTrust server for its advertised authentication
// domains and methods without starting a VPN session.
func FetchAuthMethods(server string, port int) string {
	if strings.TrimSpace(server) == "" {
		return failure("invalid_config", fmt.Errorf("server is required"))
	}
	if port == 0 {
		port = 443
	}
	methods, err := atrustclient.GetAuthInfoList(server, port, "", false, "", "")
	if err != nil {
		return failure("auth_discovery_failed", err)
	}
	return encodeResult(mobileResult{OK: true, AuthMethods: methods})
}

// Prepare negotiates a VPN session and returns addresses, routes and DNS as JSON.
// StartStack must subsequently receive the Android VpnService TUN descriptor.
func Prepare(configJSON string) string {
	return prepare(configJSON, nil)
}

func PrepareWithCallback(configJSON string, callback ChallengeCallback) string {
	return prepare(configJSON, callback)
}

func prepare(configJSON string, callback ChallengeCallback) string {
	config, err := parseConfig(configJSON)
	if err != nil {
		return failure("invalid_config", err)
	}
	sess, result, err := createSession(config, callback)
	if err != nil {
		return failure("login_failed", err)
	}
	replaceSession(sess)
	return encodeResult(result)
}

// StartProxy starts aTrust/EasyConnect with loopback SOCKS5 and/or HTTP listeners
// without consuming Android's single VpnService slot.
func StartProxy(configJSON string) string {
	return startProxy(configJSON, nil)
}

func StartProxyWithCallback(configJSON string, callback ChallengeCallback) string {
	return startProxy(configJSON, callback)
}

func startProxy(configJSON string, callback ChallengeCallback) string {
	config, err := parseConfig(configJSON)
	if err != nil {
		return failure("invalid_config", err)
	}
	if config.SocksBind == "" && config.HTTPBind == "" {
		return failure("invalid_config", fmt.Errorf("at least one proxy listener is required"))
	}
	sess, result, err := createSession(config, callback)
	if err != nil {
		return failure("login_failed", err)
	}
	if err = sess.startProxy(config, &result); err != nil {
		sess.close()
		return failure("proxy_start_failed", err)
	}
	replaceSession(sess)
	return encodeResult(result)
}

// Login preserves compatibility with the original EasyConnect-only Android app.
func Login(server string, username string, password string) string {
	host, portText, splitErr := net.SplitHostPort(server)
	port := 443
	if splitErr != nil {
		host = server
	} else {
		_, _ = fmt.Sscanf(portText, "%d", &port)
	}
	config, _ := json.Marshal(mobileConfig{
		Protocol: "easyconnect", Server: host, Port: port,
		Username: username, Password: password,
	})
	var result mobileResult
	_ = json.Unmarshal([]byte(Prepare(string(config))), &result)
	return result.Address
}

func DebugLogin(server string, username string, password string) string {
	log.EnableDebug()
	return Login(server, username, password)
}

func StartStack(fd int) string {
	sessionMu.Lock()
	sess := activeSession
	sessionMu.Unlock()
	if sess == nil || sess.client == nil {
		return failure("no_active_session", fmt.Errorf("no active session"))
	}
	stack, err := tun.NewStack(sess.client, false, false, nil)
	if err != nil {
		log.Printf("create Android TUN stack: %v", err)
		return failure("tun_start_failed", err)
	}
	stack.SetupTun(fd)
	sess.mu.Lock()
	sess.tunStack = stack
	sess.mu.Unlock()
	runErr := stack.RunWithError()
	sess.mu.Lock()
	if sess.tunStack == stack {
		sess.tunStack = nil
	}
	sess.mu.Unlock()
	if runErr != nil {
		return failure("tun_stopped", runErr)
	}
	return encodeResult(mobileResult{OK: true})
}

func Logout() { Stop() }

func Stop() {
	sessionMu.Lock()
	sess := activeSession
	activeSession = nil
	sessionMu.Unlock()
	if sess != nil {
		sess.close()
	}
}

// ResourceSnapshot returns a credential-free view of the active server policy.
func ResourceSnapshot() string {
	sessionMu.Lock()
	sess := activeSession
	sessionMu.Unlock()
	if sess == nil || sess.client == nil {
		return failure("no_active_session", fmt.Errorf("no active session"))
	}
	snapshot := resourceSnapshot{}
	if ip, err := sess.client.IP(); err == nil {
		snapshot.VirtualIP = ip.String()
	}
	snapshot.DNSServers, _ = sess.client.DNSServers()
	if resources, err := sess.client.IPResources(); err == nil {
		for _, resource := range resources {
			snapshot.IPResources = append(snapshot.IPResources, snapshotIPResource{
				IPMin: resource.IPMin.String(), IPMax: resource.IPMax.String(),
				PortMin: resource.PortMin, PortMax: resource.PortMax, Protocol: resource.Protocol,
				AppID: resource.AppID, NodeGroupID: resource.NodeGroupID, EnableTCPPrefL3: resource.EnableTCPPrefL3,
			})
		}
	}
	if domains, err := sess.client.DomainResources(); err == nil {
		names := make([]string, 0, len(domains))
		for domain := range domains {
			names = append(names, domain)
		}
		sort.Strings(names)
		for _, domain := range names {
			for _, resource := range domains[domain] {
				snapshot.DomainResources = append(snapshot.DomainResources, snapshotDomainResource{
					Domain: domain, PortMin: resource.PortMin, PortMax: resource.PortMax, Protocol: resource.Protocol,
					AppID: resource.AppID, NodeGroupID: resource.NodeGroupID,
					EnableTCPPrefL3: resource.EnableTCPPrefL3, AddrPretend: resource.AddrPretend,
				})
			}
		}
	}
	if dnsResources, err := sess.client.DNSResource(); err == nil {
		snapshot.DNSResources = make(map[string][]string, len(dnsResources))
		for domain, ips := range dnsResources {
			for _, ip := range ips {
				snapshot.DNSResources[domain] = append(snapshot.DNSResources[domain], ip.String())
			}
		}
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return failure("snapshot_failed", err)
	}
	return string(data)
}

func parseConfig(value string) (mobileConfig, error) {
	var config mobileConfig
	if err := json.Unmarshal([]byte(value), &config); err != nil {
		return config, err
	}
	if config.Protocol == "" {
		config.Protocol = "atrust"
	}
	if config.Server == "" {
		return config, fmt.Errorf("server is required")
	}
	if config.Port == 0 {
		config.Port = 443
	}
	if config.RemoteDNS == "" {
		config.RemoteDNS = "auto"
	}
	if config.DNSTTL <= 0 {
		config.DNSTTL = 3600
	}
	if config.UpdateBestNodesInterval < 0 {
		config.UpdateBestNodesInterval = 300
	}
	if config.SessionRefreshInterval < 0 {
		config.SessionRefreshInterval = 1800
	}
	return config, nil
}

func createSession(config mobileConfig, callback ChallengeCallback) (*mobileSession, mobileResult, error) {
	log.Init()
	atrustclient.SetEmbeddedMode(func(err error) {
		log.Printf("session-expired event: %v", err)
	})
	// Android shares this process with the UI, so a failing data plane must be
	// reported instead of aborting the application.
	gvisor.SetMobileMode(func(err error) {
		log.Printf("stack fatal error: %v", err)
	})
	underlayDialer, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		return nil, mobileResult{}, err
	}
	sess := &mobileSession{underlay: underlayDialer}
	var clientData []byte
	var challengeHandler authchallenge.Handler
	if callback != nil {
		challengeHandler = callbackChallengeHandler{callback: callback}
	}

	switch strings.ToLower(config.Protocol) {
	case "easyconnect":
		vpnClient := easyconnectclient.NewClient(easyconnectclient.Options{
			Server:           net.JoinHostPort(config.Server, fmt.Sprintf("%d", config.Port)),
			Auth:             easyconnectclient.AuthOptions{Username: config.Username, Password: config.Password, TOTPSecret: config.TOTPSecret},
			Resources:        easyconnectclient.ResourceOptions{Fetch: !config.DisableConfig, IncludeDomains: true},
			UnderlayDialer:   underlayDialer,
			ChallengeHandler: challengeHandler,
		})
		if err = vpnClient.Setup(); err != nil {
			vpnClient.Close()
			_ = underlayDialer.Close()
			return nil, mobileResult{}, err
		}
		sess.client = vpnClient
	case "atrust":
		authType := config.AuthType
		if authType != "" && !strings.HasPrefix(authType, "auth/") {
			authType = "auth/" + authType
		}
		method, methodErr := auth.NewLoginMethod(auth.LoginMethodOptions{
			AuthType: authType, Username: config.Username, Password: config.Password,
			Phone: config.Phone, Domain: config.LoginDomain,
		})
		if methodErr != nil {
			_ = underlayDialer.Close()
			return nil, mobileResult{}, methodErr
		}
		vpnClient := atrustclient.NewClient(atrustclient.ClientOptions{
			Session:        atrustclient.SessionOptions{Username: config.Username},
			UnderlayDialer: underlayDialer,
		})
		var savedClientData []byte
		if config.ClientData != "" {
			savedClientData = []byte(config.ClientData)
		}
		clientData, err = vpnClient.Setup(atrustclient.SetupOptions{
			ServerAddress: config.Server, ServerPort: config.Port, LoginMethod: method,
			TOTPSecret: config.TOTPSecret, ClientData: savedClientData,
			ChallengeHandler:         challengeHandler,
			BestNodesRefreshInterval: time.Duration(config.UpdateBestNodesInterval) * time.Second,
			SessionRefreshInterval:   time.Duration(config.SessionRefreshInterval) * time.Second,
		})
		if err != nil {
			vpnClient.Close()
			_ = underlayDialer.Close()
			return nil, mobileResult{}, err
		}
		sess.client = vpnClient
	default:
		_ = underlayDialer.Close()
		return nil, mobileResult{}, fmt.Errorf("unsupported protocol %q", config.Protocol)
	}

	result, err := negotiatedResult(sess.client)
	if err != nil {
		sess.close()
		return nil, mobileResult{}, err
	}
	result.ClientData = string(clientData)
	return sess, result, nil
}

func negotiatedResult(vpnClient client.Client) (mobileResult, error) {
	ip, err := vpnClient.IP()
	if err != nil {
		return mobileResult{}, err
	}
	result := mobileResult{OK: true, Address: ip.String(), PrefixLength: 32, MTU: 1400}
	if ipSet, setErr := vpnClient.IPSet(); setErr == nil && ipSet != nil {
		for _, prefix := range ipSet.Prefixes() {
			result.Routes = append(result.Routes, prefix.String())
		}
	}
	result.DNSServers, _ = vpnClient.DNSServers()
	if domains, domainErr := vpnClient.DomainResources(); domainErr == nil {
		for domain := range domains {
			result.DomainResources = append(result.DomainResources, domain)
		}
	}
	return result, nil
}

func (s *mobileSession) startProxy(config mobileConfig, result *mobileResult) error {
	ipResources, _ := s.client.IPResources()
	domainResources, _ := s.client.DomainResources()
	dnsResources, _ := s.client.DNSResource()
	remoteDNS := config.RemoteDNS
	policyDNSServers, _ := s.client.DNSServers()
	if remoteDNS == "auto" {
		if len(policyDNSServers) > 0 {
			remoteDNS = policyDNSServers[0]
		} else {
			remoteDNS, _ = s.client.DNSServer()
		}
	}
	secondaryDNS := config.SecondaryDNS
	if secondaryDNS == "" || secondaryDNS == "auto" {
		// This resolver dials directly rather than through the VPN stack. Using
		// the second policy DNS here would repeat the same failed L3 path.
		secondaryDNS = "114.114.114.114"
	}
	stack, err := gvisor.NewStack(s.client)
	if err != nil {
		return err
	}
	log.Printf("mobile proxy DNS primary=%s secondary=%s", remoteDNS, secondaryDNS)
	resolver := resolve.NewResolver(stack, remoteDNS, secondaryDNS, uint64(config.DNSTTL), domainResources, dnsResources, remoteDNS != "")
	sessionMu.Lock()
	hostDNSCallback := dnsCallback
	sessionMu.Unlock()
	if hostDNSCallback != nil {
		resolver.SetExternalLookup(func(_ context.Context, host string) ([]net.IP, error) {
			value := hostDNSCallback.Resolve(host)
			var addresses []string
			if err := json.Unmarshal([]byte(value), &addresses); err != nil {
				return nil, err
			}
			ips := make([]net.IP, 0, len(addresses))
			for _, address := range addresses {
				if ip := net.ParseIP(address); ip != nil {
					ips = append(ips, ip)
				}
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("Android system DNS returned no IPv4 address")
			}
			return ips, nil
		})
		resolver.SetHistoryLookup(func(host string) []net.IP {
			value := hostDNSCallback.LookupHistory(host)
			var addresses []string
			if err := json.Unmarshal([]byte(value), &addresses); err != nil {
				return nil
			}
			ips := make([]net.IP, 0, len(addresses))
			for _, address := range addresses {
				if ip := net.ParseIP(address); ip != nil {
					ips = append(ips, ip)
				}
			}
			return ips
		})
		resolver.SetSuccessRecorder(func(host string, ip net.IP) {
			hostDNSCallback.RecordSuccess(host, ip.String())
		})
	}
	if ipSet, ipSetErr := s.client.IPSet(); ipSetErr == nil && ipSet != nil {
		resolver.SetPreferredIP(func(ip net.IP) bool {
			parsed, parseErr := netaddr.ParseIP(ip.String())
			return parseErr == nil && ipSet.Contains(parsed)
		})
	}
	for domain, address := range config.CustomDNS {
		ip := net.ParseIP(address)
		if ip == nil {
			log.Printf("ignore invalid custom DNS: %s=%s", domain, address)
			continue
		}
		resolver.SetPermanentDNS(domain, ip)
		log.Printf("custom DNS: %s -> %s", domain, ip)
	}
	stack.SetupResolve(service.NewDnsServer(resolver, []string{remoteDNS, secondaryDNS}))
	stack.SetupIPPool(resolver.IPPool)
	s.gvisor = stack
	s.resolver = resolver
	go stack.Run()

	vpnDialer := dial.NewDialer(stack, resolver, ipResources, config.ProxyAll, "")
	if config.SocksBind != "" {
		closer, startErr := service.StartSocks5(config.SocksBind, vpnDialer, resolver, "", "")
		if startErr != nil {
			return startErr
		}
		s.servers = append(s.servers, closer)
		result.SocksAddress = config.SocksBind
	}
	if config.HTTPBind != "" {
		closer, startErr := service.StartHTTP(config.HTTPBind, vpnDialer)
		if startErr != nil {
			return startErr
		}
		s.servers = append(s.servers, closer)
		result.HTTPAddress = config.HTTPBind
	}
	return nil
}

func (s *mobileSession) close() {
	for _, server := range s.servers {
		_ = server.Close()
	}
	if s.resolver != nil {
		s.resolver.Close()
	}
	if s.gvisor != nil {
		s.gvisor.Close()
	}
	s.mu.Lock()
	activeTunStack := s.tunStack
	s.tunStack = nil
	s.mu.Unlock()
	if activeTunStack != nil {
		activeTunStack.Close()
	}
	if closer, ok := s.client.(interface{ Close() }); ok {
		closer.Close()
	}
	if s.underlay != nil {
		_ = s.underlay.Close()
	}
}

func replaceSession(next *mobileSession) {
	Stop()
	sessionMu.Lock()
	activeSession = next
	sessionMu.Unlock()
}

func failure(code string, err error) string {
	return encodeResult(mobileResult{OK: false, ErrorCode: code, ErrorMessage: err.Error()})
}

func encodeResult(result mobileResult) string {
	data, _ := json.Marshal(result)
	return string(data)
}
