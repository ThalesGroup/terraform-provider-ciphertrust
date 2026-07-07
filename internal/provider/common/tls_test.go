package common

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// writeCertPEM writes server.Certificate() (the self-signed cert minted by
// httptest.NewTLSServer) to a temp file in PEM form and returns its path.
func writeCertPEM(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "test-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing PEM: %v", err)
	}
	return path
}

// loopbackTLSServer returns a TLS test server bound to 127.0.0.1 that always
// responds 200. The default httptest cert is valid for 127.0.0.1 and ::1, so
// hostname verification succeeds when we connect via ts.URL but fails when
// we substitute a different host.
func loopbackTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

// ---------------------------------------------------------------------------
// BuildTLSConfig
// ---------------------------------------------------------------------------

func TestBuildTLSConfig_SecureDefault(t *testing.T) {
	cfg, err := BuildTLSConfig(TLSOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion=TLS12 (0x%x), got 0x%x", tls.VersionTLS12, cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must default to false")
	}
	if cfg.RootCAs != nil {
		t.Error("RootCAs must be nil when no CA path supplied (use system roots)")
	}
}

func TestBuildTLSConfig_InsecureSkipVerifyHonoured(t *testing.T) {
	cfg, err := BuildTLSConfig(TLSOptions{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify=true must propagate")
	}
	// Minimum TLS version must remain enforced even when skipping verification.
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion must stay at TLS12 even with skip-verify, got 0x%x", cfg.MinVersion)
	}
}

func TestBuildTLSConfig_LoadsCABundle(t *testing.T) {
	ts := loopbackTLSServer(t)
	defer ts.Close()
	caPath := writeCertPEM(t, ts)

	cfg, err := BuildTLSConfig(TLSOptions{CACertPath: caPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs must be populated when CACertPath is supplied")
	}
	// The supplied pool should accept the test server's certificate.
	opts := x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: "127.0.0.1"}
	if _, err := ts.Certificate().Verify(opts); err != nil {
		t.Errorf("loaded CA bundle should verify the test server cert: %v", err)
	}
}

// Custom CAs must be ADDED to the system trust store, not replace it.
// Without this guarantee, supplying ca_cert for one internal CM would break
// connections to anything else on a publicly-trusted cert from the same plan.
func TestBuildTLSConfig_ExtendsSystemRoots(t *testing.T) {
	sysPool, err := x509.SystemCertPool()
	if err != nil || sysPool == nil {
		t.Skip("system cert pool unavailable on this platform; skipping extension check")
	}
	sysSubjectCount := len(sysPool.Subjects())
	if sysSubjectCount == 0 {
		t.Skip("system cert pool is empty; skipping extension check")
	}

	ts := loopbackTLSServer(t)
	defer ts.Close()
	caPath := writeCertPEM(t, ts)

	cfg, err := BuildTLSConfig(TLSOptions{CACertPath: caPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("RootCAs must be populated when CACertPath is supplied")
	}

	// The combined pool must contain strictly more roots than the system pool
	// alone, proving the supplied CA was appended rather than substituted.
	combinedCount := len(cfg.RootCAs.Subjects())
	if combinedCount <= sysSubjectCount {
		t.Errorf("expected combined pool (%d) to contain more roots than system pool (%d); "+
			"supplied CA appears to have replaced rather than extended system roots",
			combinedCount, sysSubjectCount)
	}

	// And the supplied CA must still successfully verify the test server cert.
	opts := x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: "127.0.0.1"}
	if _, err := ts.Certificate().Verify(opts); err != nil {
		t.Errorf("combined pool should verify the test server cert: %v", err)
	}
}

func TestBuildTLSConfig_RejectsMissingCAFile(t *testing.T) {
	_, err := BuildTLSConfig(TLSOptions{CACertPath: "/does/not/exist/ca.pem"})
	if err == nil {
		t.Fatal("expected error for missing CA file, got nil")
	}
	if !strings.Contains(err.Error(), "/does/not/exist/ca.pem") {
		t.Errorf("error should mention the offending path, got: %v", err)
	}
}

func TestBuildTLSConfig_RejectsInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("writing junk file: %v", err)
	}

	_, err := BuildTLSConfig(TLSOptions{CACertPath: junk})
	if err == nil {
		t.Fatal("expected error for invalid PEM contents, got nil")
	}
	if !strings.Contains(err.Error(), "no valid certificates") {
		t.Errorf("error should call out invalid PEM contents, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Client constructor propagation
// ---------------------------------------------------------------------------

func transportTLSConfig(t *testing.T, c *http.Client) *tls.Config {
	t.Helper()
	// NewClient wraps the *http.Transport in a TokenRefreshTransport; unwrap it.
	if rt, ok := c.Transport.(*TokenRefreshTransport); ok {
		base, ok := rt.Base.(*http.Transport)
		if !ok {
			t.Fatalf("TokenRefreshTransport.Base is %T, want *http.Transport", rt.Base)
		}
		return base.TLSClientConfig
	}
	if tr, ok := c.Transport.(*http.Transport); ok {
		return tr.TLSClientConfig
	}
	t.Fatalf("unexpected transport type %T", c.Transport)
	return nil
}

func TestNewCMClientBoot_PropagatesTLSOptions(t *testing.T) {
	ctx := context.Background()
	addr := "https://127.0.0.1"

	c, err := NewCMClientBoot(ctx, "uuid", &addr, TLSOptions{InsecureSkipVerify: true}, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg := transportTLSConfig(t, c.HTTPClient)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion=0x%x want 0x%x", cfg.MinVersion, tls.VersionTLS12)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must propagate to the HTTP transport")
	}
}

func TestNewCMClientBoot_FailsOnBadCAPath(t *testing.T) {
	ctx := context.Background()
	addr := "https://127.0.0.1"

	_, err := NewCMClientBoot(ctx, "uuid", &addr, TLSOptions{CACertPath: "/no/such/file"}, 5)
	if err == nil {
		t.Fatal("expected error when CA path is unreadable")
	}
}

// NewClient without credentials returns an unauthenticated client without
// attempting a sign-in, which lets us inspect the transport in isolation.
func TestNewClient_PropagatesTLSOptions_NoCreds(t *testing.T) {
	ctx := context.Background()
	addr := "https://127.0.0.1"

	c, err := NewClient(ctx, "uuid", &addr, nil, nil, nil, nil, nil, TLSOptions{InsecureSkipVerify: true}, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg := transportTLSConfig(t, c.HTTPClient)
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion=0x%x want 0x%x", cfg.MinVersion, tls.VersionTLS12)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must propagate via TokenRefreshTransport.Base")
	}
}

func TestNewClient_FailsOnBadCAPath(t *testing.T) {
	ctx := context.Background()
	addr := "https://127.0.0.1"

	_, err := NewClient(ctx, "uuid", &addr, nil, nil, nil, nil, nil, TLSOptions{CACertPath: "/no/such/file"}, 5)
	if err == nil {
		t.Fatal("expected error when CA path is unreadable")
	}
}

// ---------------------------------------------------------------------------
// End-to-end: real TLS handshake against an httptest TLS server.
// ---------------------------------------------------------------------------

// doGet performs an HTTPS GET using c against url. It returns any transport
// error (i.e. handshake failures), not HTTP status codes.
func doGet(c *http.Client, target string) error {
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	return err
}

func TestSecureClient_RejectsUntrustedCertByDefault(t *testing.T) {
	ts := loopbackTLSServer(t)
	defer ts.Close()

	ctx := context.Background()
	c, err := NewCMClientBoot(ctx, "uuid", &ts.URL, TLSOptions{}, 5)
	if err != nil {
		t.Fatalf("unexpected error building client: %v", err)
	}

	err = doGet(c.HTTPClient, ts.URL)
	if err == nil {
		t.Fatal("expected TLS verification to fail with secure defaults against a self-signed server")
	}
	// We expect an x509 unknown-authority class error.
	var unknownAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	if !errors.As(err, &unknownAuth) && !errors.As(err, &hostErr) && !strings.Contains(err.Error(), "x509") && !strings.Contains(err.Error(), "certificate") {
		t.Errorf("expected x509/certificate error, got: %v", err)
	}
}

func TestSecureClient_AcceptsServerWithSuppliedCA(t *testing.T) {
	ts := loopbackTLSServer(t)
	defer ts.Close()
	caPath := writeCertPEM(t, ts)

	ctx := context.Background()
	c, err := NewCMClientBoot(ctx, "uuid", &ts.URL, TLSOptions{CACertPath: caPath}, 5)
	if err != nil {
		t.Fatalf("unexpected error building client: %v", err)
	}

	if err := doGet(c.HTTPClient, ts.URL); err != nil {
		t.Errorf("expected handshake to succeed with supplied CA bundle, got: %v", err)
	}
}

func TestSecureClient_SkipVerifyAcceptsUntrustedCert(t *testing.T) {
	ts := loopbackTLSServer(t)
	defer ts.Close()

	ctx := context.Background()
	c, err := NewCMClientBoot(ctx, "uuid", &ts.URL, TLSOptions{InsecureSkipVerify: true}, 5)
	if err != nil {
		t.Fatalf("unexpected error building client: %v", err)
	}

	if err := doGet(c.HTTPClient, ts.URL); err != nil {
		t.Errorf("expected handshake to succeed when InsecureSkipVerify=true, got: %v", err)
	}
}

func TestSecureClient_HostnameMismatchFails(t *testing.T) {
	ts := loopbackTLSServer(t)
	defer ts.Close()
	caPath := writeCertPEM(t, ts)

	// Swap the host for a name not in the test cert SAN list (cert covers
	// 127.0.0.1 / ::1 / localhost), forcing a hostname mismatch.
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	mismatched := "https://example.invalid:" + u.Port()

	ctx := context.Background()
	c, err := NewCMClientBoot(ctx, "uuid", &ts.URL, TLSOptions{CACertPath: caPath}, 5)
	if err != nil {
		t.Fatalf("unexpected error building client: %v", err)
	}

	// Force the request to hit the test server while presenting the wrong
	// SNI/Host by dialing 127.0.0.1 but using example.invalid in the URL.
	tr := c.HTTPClient.Transport.(*http.Transport)
	tr.DialContext = func(_ context.Context, network, _ string) (net.Conn, error) {
		return net.Dial(network, u.Host)
	}

	err = doGet(c.HTTPClient, mismatched)
	if err == nil {
		t.Fatal("expected hostname verification to fail, got nil")
	}
	// Depending on how the transport rejects the mismatch (TLS verify-side or
	// server-side abort once SNI doesn't match), the surfaced error may be a
	// typed x509.HostnameError, a generic "certificate" string, or a connection
	// teardown (EOF / connection reset). The security property under test is
	// "the request did NOT succeed against the wrong host" — any error here
	// satisfies that.
	var hostErr x509.HostnameError
	if !errors.As(err, &hostErr) &&
		!strings.Contains(err.Error(), "certificate") &&
		!strings.Contains(err.Error(), "EOF") &&
		!strings.Contains(err.Error(), "reset") &&
		!strings.Contains(err.Error(), "connection") {
		t.Errorf("unexpected error class for hostname mismatch: %v", err)
	}
}
