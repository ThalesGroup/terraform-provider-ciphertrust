package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Default CipherTrust Manager URL
const CipherTrustURL string = "https://10.10.10.10"

// TLSOptions carries the user-supplied TLS configuration for the HTTP client.
// The zero value is secure-by-default: certificate verification enabled, no
// custom CA bundle, and (in BuildTLSConfig) TLS 1.2 enforced as the minimum.
type TLSOptions struct {
	// InsecureSkipVerify disables certificate chain and hostname validation
	// when true. Intended for testing only.
	InsecureSkipVerify bool
	// CACertPath is the filesystem path to a PEM-encoded CA bundle that
	// supplies the root CAs used to validate the server certificate. When
	// empty the system roots are used.
	CACertPath string
}

// BuildTLSConfig produces a *tls.Config that enforces TLS 1.2 as the minimum
// version, honours InsecureSkipVerify, and adds any user-supplied CA bundle
// on top of the system trust store. It returns a clear error if the PEM file
// cannot be read or contains no valid certificates.
//
// When CACertPath is supplied the returned pool is the system root pool with
// the user's certificates appended — system trust anchors are NOT replaced.
// If the system pool cannot be loaded (e.g. on a platform where it is
// unavailable) an empty pool is used and only the supplied CAs are trusted.
func BuildTLSConfig(opts TLSOptions) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
	if opts.CACertPath != "" {
		pemBytes, err := os.ReadFile(opts.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate file %q: %w", opts.CACertPath, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("failed to parse PEM certificates from %q: no valid certificates found", opts.CACertPath)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// normalizeAddress ensures the address has an https:// scheme and no trailing slash.
func normalizeAddress(addr string) string {
	addr = strings.TrimRight(addr, "/")
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "https://" + addr
	}
	return addr
}

type CCKMProviderConfig struct {
	AwsOperationTimeout int64
	OCIOperationTimeout int64
}

// Client
type Client struct {
	CipherTrustURL   string
	HTTPClient       *http.Client
	Token            string
	CMRefreshToken   string // refresh token returned by CipherTrust Manager
	AuthData         AuthStruct
	CCKMConfig       CCKMProviderConfig
	ReplicationDelay int64
	// IsCDSPaaS is true when the provider is configured against a CDSPaaS
	// tenant (i.e. AuthData.AuthDomainPath is set). Resources that manage
	// CipherTrust Manager infrastructure use this to refuse plan-time.
	IsCDSPaaS bool
}

// Bootstrap Client for CipherTrust Manager
type CMClientBootstrap struct {
	CipherTrustURL   string
	HTTPClient       *http.Client
	CCKMConfig       CCKMProviderConfig
	ReplicationDelay int64
}

// AuthStruct
type AuthStruct struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	AuthDomain        string `json:"auth_domain,omitempty"`
	AuthDomainPath    string `json:"auth_domain_path,omitempty"`
	Domain            string `json:"domain"`
	GrantType         string `json:"grant_type,omitempty"`
	RefreshToken      string `json:"refresh_token,omitempty"`
	RenewRefreshToken bool   `json:"renew_refresh_token,omitempty"`
}

// AuthResponse
type AuthResponse struct {
	Token        string `json:"jwt"`
	RefreshToken string `json:"refresh_token"`
}

// Create new client for CM with auth details
// Usable for som bootstrap API calls
func NewCMClientBoot(ctx context.Context, uuid string, address *string, tlsOpts TLSOptions, timeout int64) (*CMClientBootstrap, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[client.go -> NewCMClientBoot]["+uuid+"]")
	tlsCfg, err := BuildTLSConfig(tlsOpts)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> NewCMClientBoot]["+uuid+"]")
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		Proxy:           http.ProxyFromEnvironment, // respects HTTPS_PROXY/NO_PROXY env vars
	}

	c := CMClientBootstrap{
		HTTPClient: &http.Client{
			Timeout:   time.Duration(timeout) * time.Second,
			Transport: tr,
		},
		// Default CM URL
		CipherTrustURL: CipherTrustURL,
	}

	if address != nil {
		c.CipherTrustURL = normalizeAddress(*address)
	}

	tflog.Trace(ctx, MSG_METHOD_END+" [client.go -> NewCMClientBoot]["+uuid+"]")
	return &c, nil
}

// Create New Client for CipherTrust Manager
//
// tenant, when non-nil and non-empty, opts the provider into the CDSPaaS
// authentication path: it is sent as auth_domain_path on the auth-token request
// (which supersedes auth_domain server-side) and Client.IsCDSPaaS is set to true.
func NewClient(ctx context.Context, uuid string, address, auth_domain, domain, username, password, tenant *string, tlsOpts TLSOptions, timeout int64) (*Client, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[client.go -> NewClient]["+uuid+"]")
	tlsCfg, err := BuildTLSConfig(tlsOpts)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> NewClient]["+uuid+"]")
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		Proxy:           http.ProxyFromEnvironment, // respects HTTPS_PROXY/NO_PROXY env vars
	}

	// Create the token refresh transport (client back-reference set below).
	refreshTransport := &TokenRefreshTransport{Base: tr}

	c := Client{
		HTTPClient: &http.Client{
			Timeout:   time.Duration(timeout) * time.Second,
			Transport: refreshTransport,
		},
		// Default URL
		CipherTrustURL: CipherTrustURL,
	}

	// Wire back-reference so the transport can access/update c.Token etc.
	refreshTransport.client = &c

	if address != nil {
		c.CipherTrustURL = normalizeAddress(*address)
	}

	// If username or password not provided, return empty client
	if username == nil || password == nil {
		return &c, nil
	}

	c.AuthData = AuthStruct{
		Username:   *username,
		Password:   *password,
		AuthDomain: *auth_domain,
		Domain:     *domain,
	}

	if tenant != nil && *tenant != "" {
		path := *tenant
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		c.AuthData.AuthDomainPath = path
		c.IsCDSPaaS = true
	}

	ar, err := c.SignIn(ctx, uuid)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> NewClient]["+uuid+"]")
		return nil, err
	}

	c.Token = ar.Token
	c.CMRefreshToken = ar.RefreshToken

	tflog.Trace(ctx, MSG_METHOD_END+" [client.go -> NewClient]["+uuid+"]")
	return &c, nil
}

func (c *Client) doRequest(ctx context.Context, uuid string, req *http.Request, jwt *string) ([]byte, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[client.go -> doRequest]["+uuid+"]")
	token := c.Token

	if jwt != nil {
		token = *jwt
	}

	var bearer = "Bearer " + token
	req.Header.Set("Authorization", bearer)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> doRequest]["+uuid+"]")
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> doRequest]["+uuid+"]")
		return nil, err
	}

	if res.StatusCode == http.StatusOK ||
		res.StatusCode == http.StatusCreated ||
		res.StatusCode == http.StatusPartialContent ||
		res.StatusCode == http.StatusAccepted ||
		res.StatusCode == http.StatusNonAuthoritativeInfo ||
		res.StatusCode == http.StatusNoContent {
		tflog.Trace(ctx, MSG_METHOD_END+"[client.go -> doRequest]["+uuid+"]")
		return body, err
	} else {
		tflog.Trace(ctx, MSG_METHOD_END+"[client.go -> doRequest]["+uuid+"]")
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}
}

func (c *CMClientBootstrap) doRequestBootstrap(ctx context.Context, uuid string, req *http.Request) ([]byte, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[client.go -> doRequestBootstrap]["+uuid+"]")

	req.Header.Add("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> doRequestBootstrap]["+uuid+"]")
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> doRequestBootstrap]["+uuid+"]")
		return nil, err
	}

	if res.StatusCode == http.StatusOK ||
		res.StatusCode == http.StatusCreated ||
		res.StatusCode == http.StatusPartialContent ||
		res.StatusCode == http.StatusAccepted ||
		res.StatusCode == http.StatusNonAuthoritativeInfo ||
		res.StatusCode == http.StatusNoContent {
		tflog.Trace(ctx, MSG_METHOD_END+"[client.go -> doRequest]["+uuid+"]")
		return body, err
	} else {
		tflog.Trace(ctx, MSG_METHOD_END+"[client.go -> doRequest]["+uuid+"]")
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}
}
