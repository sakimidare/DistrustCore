package mobile

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	atrustclient "github.com/mythologyli/zju-connect/client/atrust"
	"github.com/mythologyli/zju-connect/client/atrust/auth"
	easyconnectclient "github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tun"
	"github.com/mythologyli/zju-connect/underlay"
)

type mobileConfig struct {
	Protocol      string `json:"protocol"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	TOTPSecret    string `json:"totpSecret"`
	AuthType      string `json:"authType"`
	LoginDomain   string `json:"loginDomain"`
	Phone         string `json:"phone"`
	ClientData    string `json:"clientData"`
	SocksBind     string `json:"socksBind"`
	HTTPBind      string `json:"httpBind"`
	RemoteDNS     string `json:"remoteDns"`
	SecondaryDNS  string `json:"secondaryDns"`
	ProxyAll      bool   `json:"proxyAll"`
	DisableConfig bool   `json:"disableServerConfig"`
}

type mobileResult struct {
	OK           bool     `json:"ok"`
	ErrorCode    string   `json:"errorCode,omitempty"`
	ErrorMessage string   `json:"errorMessage,omitempty"`
	Address      string   `json:"address,omitempty"`
	PrefixLength int      `json:"prefixLength,omitempty"`
	MTU          int      `json:"mtu,omitempty"`
	Routes       []string `json:"routes,omitempty"`
	DNSServers   []string `json:"dnsServers,omitempty"`
	SocksAddress string   `json:"socksAddress,omitempty"`
	HTTPAddress  string   `json:"httpAddress,omitempty"`
	ClientData   string   `json:"clientData,omitempty"`
}

type mobileSession struct {
	client   client.Client
	underlay *underlay.Dialer
	gvisor   *gvisor.Stack
	resolver *resolve.Resolver
	servers  []io.Closer
}

var sessionMu sync.Mutex
var activeSession *mobileSession

// Capabilities reports only features implemented by this mobile binding.
func Capabilities() string {
	return `{"apiVersion":2,"easyConnectVpn":true,"aTrustPasswordVpn":true,"localSocks5":true,"localHttp":true,"interactiveAuth":false}`
}

// Prepare negotiates a VPN session and returns addresses, routes and DNS as JSON.
// StartStack must subsequently receive the Android VpnService TUN descriptor.
func Prepare(configJSON string) string {
	config, err := parseConfig(configJSON)
	if err != nil {
		return failure("invalid_config", err)
	}
	sess, result, err := createSession(config)
	if err != nil {
		return failure("login_failed", err)
	}
	replaceSession(sess)
	return encodeResult(result)
}

// StartProxy starts aTrust/EasyConnect with loopback SOCKS5 and/or HTTP listeners
// without consuming Android's single VpnService slot.
func StartProxy(configJSON string) string {
	config, err := parseConfig(configJSON)
	if err != nil {
		return failure("invalid_config", err)
	}
	if config.SocksBind == "" && config.HTTPBind == "" {
		return failure("invalid_config", fmt.Errorf("at least one proxy listener is required"))
	}
	sess, result, err := createSession(config)
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

func StartStack(fd int) {
	sessionMu.Lock()
	sess := activeSession
	sessionMu.Unlock()
	if sess == nil || sess.client == nil {
		return
	}
	stack, err := tun.NewStack(sess.client, false, false, nil)
	if err != nil {
		log.Printf("create Android TUN stack: %v", err)
		return
	}
	stack.SetupTun(fd)
	stack.Run()
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
	return config, nil
}

func createSession(config mobileConfig) (*mobileSession, mobileResult, error) {
	log.Init()
	underlayDialer, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		return nil, mobileResult{}, err
	}
	sess := &mobileSession{underlay: underlayDialer}
	var clientData []byte

	switch strings.ToLower(config.Protocol) {
	case "easyconnect":
		vpnClient := easyconnectclient.NewClient(easyconnectclient.Options{
			Server:         net.JoinHostPort(config.Server, fmt.Sprintf("%d", config.Port)),
			Auth:           easyconnectclient.AuthOptions{Username: config.Username, Password: config.Password, TOTPSecret: config.TOTPSecret},
			Resources:      easyconnectclient.ResourceOptions{Fetch: !config.DisableConfig, IncludeDomains: true},
			UnderlayDialer: underlayDialer,
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
		if authType != "" && authType != "auth/psw" {
			_ = underlayDialer.Close()
			return nil, mobileResult{}, fmt.Errorf("mobile API currently supports aTrust password auth only")
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
			BestNodesRefreshInterval: 5 * time.Minute,
			SessionRefreshInterval:   30 * time.Minute,
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
	return result, nil
}

func (s *mobileSession) startProxy(config mobileConfig, result *mobileResult) error {
	ipResources, _ := s.client.IPResources()
	domainResources, _ := s.client.DomainResources()
	dnsResources, _ := s.client.DNSResource()
	remoteDNS := config.RemoteDNS
	if remoteDNS == "auto" {
		remoteDNS, _ = s.client.DNSServer()
	}
	stack, err := gvisor.NewStack(s.client)
	if err != nil {
		return err
	}
	resolver := resolve.NewResolver(stack, remoteDNS, config.SecondaryDNS, 3600, domainResources, dnsResources, remoteDNS != "")
	stack.SetupResolve(service.NewDnsServer(resolver, []string{remoteDNS, config.SecondaryDNS}))
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
