// Copyright (c) Thales Group
// SPDX-License-Identifier: MIT

// provider_config_unit_test.go contains unit tests for provider configuration
// loading and precedence. The tests cover:
//   - validation errors when required fields are absent
//   - all provider settings honoured when supplied via the provider block
//   - all provider settings honoured when supplied via environment variables
//   - all provider settings honoured when supplied via the config file
//   - provider block takes precedence over environment variables
//
// None of these tests require TF_ACC=1 or a live CipherTrust Manager.
// The settings tests call Configure directly against a local TLS test server
// that handles only the two endpoints invoked during provider initialisation.
package provider

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

// startMockCM starts a local TLS server that handles the two CM endpoints
// called during provider initialisation:
//   - POST /api/v1/auth/tokens  -- returns a minimal fake JWT response
//   - GET  /api/v1/cluster      -- returns nodeCount=1 (not clustered)
//
// The server is registered for automatic closure via t.Cleanup. Returns the
// server base URL (e.g. "https://127.0.0.1:PORT").
func startMockCM(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "auth/tokens"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"jwt":           "unit-test-fake-token",
				"refresh_token": "unit-test-fake-refresh",
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "cluster"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"nodeCount": 1})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// setHomeDir overrides the OS home-directory for the duration of t so that the
// provider config-file reader sees a clean temporary directory with no
// ~/.ciphertrust/config present. Both HOME (Unix) and USERPROFILE (Windows)
// are set so the test behaves consistently across platforms.
func setHomeDir(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

// clearEnvVars temporarily unsets each named environment variable for the
// duration of t, restoring the original value (or re-unsetting it) via
// t.Cleanup. Unlike t.Setenv, this truly removes the variable rather than
// setting it to the empty string, which prevents Configure from treating an
// empty string as a valid override.
func clearEnvVars(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		name := name
		old, had := os.LookupEnv(name)
		_ = os.Unsetenv(name)
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(name, old)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

// buildProviderConfigure constructs a provider.ConfigureRequest whose
// provider-block values are exactly those supplied in the maps. Every attribute
// not listed is set to null (i.e. absent from the provider block). String,
// integer (Int64), and boolean attributes are supported; any key not present
// in the provider schema is silently ignored.
func buildProviderConfigure(
	t *testing.T,
	strs map[string]string,
	ints map[string]int64,
	bools map[string]bool,
) provider.ConfigureRequest {
	t.Helper()
	ctx := context.Background()
	p := &ciphertrustProvider{}
	var sr provider.SchemaResponse
	p.Schema(ctx, provider.SchemaRequest{}, &sr)

	// Derive the tftypes.Object type from the provider schema so we can build
	// a correctly typed raw value without hard-coding the attribute type map.
	objType := sr.Schema.Type().TerraformType(ctx).(tftypes.Object)

	// Start with every attribute null, then apply caller-supplied values.
	vals := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for k, at := range objType.AttributeTypes {
		vals[k] = tftypes.NewValue(at, nil)
	}
	for k, v := range strs {
		vals[k] = tftypes.NewValue(tftypes.String, v)
	}
	for k, v := range ints {
		vals[k] = tftypes.NewValue(tftypes.Number, new(big.Float).SetInt64(v))
	}
	for k, v := range bools {
		vals[k] = tftypes.NewValue(tftypes.Bool, v)
	}

	raw := tftypes.NewValue(objType, vals)
	return provider.ConfigureRequest{
		Config: tfsdk.Config{Raw: raw, Schema: sr.Schema},
	}
}

// runProviderConfigure calls p.Configure with req, asserts no diagnostic
// errors, and returns the *common.Client stored in ResourceData. It also
// registers a t.Cleanup to close any log file handle left open by Configure.
func runProviderConfigure(t *testing.T, p *ciphertrustProvider, req provider.ConfigureRequest) *common.Client {
	t.Helper()
	var resp provider.ConfigureResponse
	p.Configure(context.Background(), req, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Configure returned unexpected errors:\n%s", resp.Diagnostics)
	}
	client, ok := resp.ResourceData.(*common.Client)
	if !ok {
		t.Fatalf("ResourceData is not *common.Client: %T", resp.ResourceData)
	}
	t.Cleanup(func() {
		if p.logFileHandle != nil {
			_ = p.logFileHandle.Close()
			p.logFileHandle = nil
		}
	})
	return client
}

// tlsInsecureSkipVerify returns the InsecureSkipVerify flag on the TLS config
// wired into client's HTTP transport. The transport chain is:
//
//	*common.TokenRefreshTransport -> *http.Transport -> tls.Config
func tlsInsecureSkipVerify(t *testing.T, client *common.Client) bool {
	t.Helper()
	rt, ok := client.HTTPClient.Transport.(*common.TokenRefreshTransport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", client.HTTPClient.Transport)
	}
	ht, ok := rt.Base.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected base transport type: %T", rt.Base)
	}
	if ht.TLSClientConfig == nil {
		return false
	}
	return ht.TLSClientConfig.InsecureSkipVerify
}

// ---------------------------------------------------------------------------
// Validation-error tests (direct Configure call -- no TF_ACC required)
// ---------------------------------------------------------------------------
//
// These tests verify that Configure returns the expected diagnostic error when
// a required field is absent from all three configuration sources (provider
// block, environment variables, and config file). Using direct p.Configure()
// calls avoids a dependency on any specific data source type name while still
// exercising the exact same code path that Terraform invokes at plan time.

// assertDiagSummaryContains fails the test if no error diagnostic has a
// Summary containing substr.
func assertDiagSummaryContains(t *testing.T, resp *provider.ConfigureResponse, substr string) {
	t.Helper()
	if !resp.Diagnostics.HasError() {
		t.Fatalf("expected Configure to return an error containing %q, but no error was returned", substr)
	}
	for _, d := range resp.Diagnostics.Errors() {
		if strings.Contains(d.Summary(), substr) {
			return
		}
	}
	t.Errorf("expected a diagnostic with summary containing %q; got diagnostics: %s", substr, resp.Diagnostics)
}

// TestUnit_Provider_ValidationError_MissingAddress verifies that omitting the
// address from every configuration source causes Configure to fail with the
// "Missing CipherTrust API IP/FQDN" diagnostic.
func TestUnit_Provider_ValidationError_MissingAddress(t *testing.T) {
	dir := t.TempDir()
	setHomeDir(t, dir)
	clearEnvVars(t, "CIPHERTRUST_ADDRESS")

	p := &ciphertrustProvider{}
	req := buildProviderConfigure(t,
		map[string]string{"username": "admin", "password": "pass", "bootstrap": "no", "log_level": "off"},
		nil, nil,
	)
	var resp provider.ConfigureResponse
	p.Configure(context.Background(), req, &resp)
	assertDiagSummaryContains(t, &resp, "Missing CipherTrust API IP/FQDN")
}

// TestUnit_Provider_ValidationError_MissingUsername verifies that omitting the
// username from every configuration source causes Configure to fail with the
// "Missing CipherTrust API Username" diagnostic.
func TestUnit_Provider_ValidationError_MissingUsername(t *testing.T) {
	dir := t.TempDir()
	setHomeDir(t, dir)
	clearEnvVars(t, "CIPHERTRUST_USERNAME")

	p := &ciphertrustProvider{}
	req := buildProviderConfigure(t,
		map[string]string{"address": "https://192.0.2.1", "password": "pass", "bootstrap": "no", "log_level": "off"},
		nil, nil,
	)
	var resp provider.ConfigureResponse
	p.Configure(context.Background(), req, &resp)
	assertDiagSummaryContains(t, &resp, "Missing CipherTrust API Username")
}

// TestUnit_Provider_ValidationError_MissingPassword verifies that omitting the
// password from every configuration source causes Configure to fail with the
// "Missing CipherTrust API Password" diagnostic.
func TestUnit_Provider_ValidationError_MissingPassword(t *testing.T) {
	dir := t.TempDir()
	setHomeDir(t, dir)
	clearEnvVars(t, "CIPHERTRUST_PASSWORD")

	p := &ciphertrustProvider{}
	req := buildProviderConfigure(t,
		map[string]string{"address": "https://192.0.2.1", "username": "admin", "bootstrap": "no", "log_level": "off"},
		nil, nil,
	)
	var resp provider.ConfigureResponse
	p.Configure(context.Background(), req, &resp)
	assertDiagSummaryContains(t, &resp, "Missing CipherTrust API Password")
}

// ---------------------------------------------------------------------------
// Settings-honoured tests (direct Configure call against a mock CM server)
// ---------------------------------------------------------------------------
//
// Each test below verifies that a specific configuration source is correctly
// applied to every provider attribute and that each attribute ends up on the
// right field of the *common.Client. Using deliberately distinct values for
// every numeric attribute guards against the class of bug where one field is
// accidentally assigned to the wrong variable (for example replication_delay_ms
// being written to oci_operation_timeout).

// settingsVerify checks that all verifiable client fields match the expected
// set of values. It is called by each settings-honoured test with different
// expected values depending on which source is being exercised.
func settingsVerify(
	t *testing.T,
	p *ciphertrustProvider,
	client *common.Client,
	wantURL string,
	wantUsername string,
	wantPassword string,
	wantDomain string,
	wantAuthDomain string,
	wantRestTimeout time.Duration,
	wantAWSTimeout int64,
	wantOCITimeout int64,
	wantRepDelay int64,
	wantSSLSkip bool,
	wantLogFile string,
	wantLogLevel hclog.Level,
) {
	t.Helper()

	if client.CipherTrustURL != wantURL {
		t.Errorf("CipherTrustURL: want %q, got %q", wantURL, client.CipherTrustURL)
	}
	if client.AuthData.Username != wantUsername {
		t.Errorf("Username: want %q, got %q", wantUsername, client.AuthData.Username)
	}
	if client.AuthData.Password != wantPassword {
		t.Errorf("Password: want %q, got %q", wantPassword, client.AuthData.Password)
	}
	if client.AuthData.Domain != wantDomain {
		t.Errorf("Domain: want %q, got %q", wantDomain, client.AuthData.Domain)
	}
	if client.AuthData.AuthDomain != wantAuthDomain {
		t.Errorf("AuthDomain: want %q, got %q", wantAuthDomain, client.AuthData.AuthDomain)
	}
	if client.HTTPClient.Timeout != wantRestTimeout {
		t.Errorf("rest_api_timeout -> HTTPClient.Timeout: want %v, got %v", wantRestTimeout, client.HTTPClient.Timeout)
	}
	if client.CCKMConfig.AwsOperationTimeout != wantAWSTimeout {
		t.Errorf("aws_operation_timeout -> CCKMConfig.AwsOperationTimeout: want %d, got %d", wantAWSTimeout, client.CCKMConfig.AwsOperationTimeout)
	}
	if client.CCKMConfig.OCIOperationTimeout != wantOCITimeout {
		t.Errorf("oci_operation_timeout -> CCKMConfig.OCIOperationTimeout: want %d, got %d", wantOCITimeout, client.CCKMConfig.OCIOperationTimeout)
	}
	// This check is the direct regression guard for the bug where
	// replication_delay_ms was inadvertently assigned to oci_operation_timeout.
	if client.ReplicationDelay != wantRepDelay {
		t.Errorf("replication_delay_ms -> ReplicationDelay: want %d, got %d"+
			" (possible replication_delay/oci_timeout confusion)",
			wantRepDelay, client.ReplicationDelay)
	}
	if got := tlsInsecureSkipVerify(t, client); got != wantSSLSkip {
		t.Errorf("no_ssl_verify -> InsecureSkipVerify: want %v, got %v", wantSSLSkip, got)
	}
	if wantLogFile != "" {
		if p.logFileHandle == nil {
			t.Fatal("p.logFileHandle is nil after Configure -- log_file was not applied")
		}
		if p.logFileHandle.Name() != wantLogFile {
			t.Errorf("log_file -> logFileHandle.Name(): want %q, got %q", wantLogFile, p.logFileHandle.Name())
		}
	}
	if client.Log.GetLevel() != wantLogLevel {
		t.Errorf("log_level -> Log.GetLevel(): want %d, got %d",
			wantLogLevel, client.Log.GetLevel())
	}
}

// TestUnit_Provider_SettingsHonoured_ProviderBlock verifies that every provider
// attribute is taken from the provider block when it is the sole configuration
// source. Distinct numeric values (11/22/33/44) ensure no cross-assignment goes
// undetected.
func TestUnit_Provider_SettingsHonoured_ProviderBlock(t *testing.T) {
	cmURL := startMockCM(t)
	dir := t.TempDir()
	setHomeDir(t, dir)

	// Remove env vars so only the provider block is active.
	clearEnvVars(t,
		"CIPHERTRUST_ADDRESS", "CIPHERTRUST_USERNAME", "CIPHERTRUST_PASSWORD",
		"CIPHERTRUST_DOMAIN", "CIPHERTRUST_AUTH_DOMAIN",
		"REST_API_TIMEOUT", "CIPHERTRUST_REPLICATION_DELAY", "NO_SSL_VERIFY",
	)

	logFile := filepath.Join(dir, "block-test.log")
	p := &ciphertrustProvider{}
	req := buildProviderConfigure(t,
		map[string]string{
			"address":     cmURL,
			"username":    "block-user",
			"password":    "block-pass",
			"domain":      "block-domain",
			"auth_domain": "block-auth",
			"bootstrap":   "no",
			"log_file":    logFile,
			"log_level":   "debug",
		},
		map[string]int64{
			"rest_api_timeout":      44,
			"aws_operation_timeout": 11,
			"oci_operation_timeout": 22,
			"replication_delay_ms":  33,
		},
		map[string]bool{
			"no_ssl_verify": true,
		},
	)

	client := runProviderConfigure(t, p, req)
	settingsVerify(t, p, client,
		cmURL, "block-user", "block-pass", "block-domain", "block-auth",
		44*time.Second, 11, 22, 33, true, logFile, hclog.LevelFromString("debug"),
	)
}

// TestUnit_Provider_SettingsHonoured_EnvVars verifies that the eight provider
// attributes that have corresponding environment variables are taken from those
// variables when the provider block is empty. Attributes without env vars
// (aws_operation_timeout, oci_operation_timeout, log_file, log_level) default
// to their coded defaults or are supplied via the provider block.
func TestUnit_Provider_SettingsHonoured_EnvVars(t *testing.T) {
	cmURL := startMockCM(t)
	dir := t.TempDir()
	setHomeDir(t, dir)

	// Set env vars with distinct recognisable values.
	t.Setenv("CIPHERTRUST_ADDRESS", cmURL)
	t.Setenv("CIPHERTRUST_USERNAME", "env-user")
	t.Setenv("CIPHERTRUST_PASSWORD", "env-pass")
	t.Setenv("CIPHERTRUST_DOMAIN", "env-domain")
	t.Setenv("CIPHERTRUST_AUTH_DOMAIN", "env-auth")
	t.Setenv("REST_API_TIMEOUT", "55")
	t.Setenv("CIPHERTRUST_REPLICATION_DELAY", "66")
	t.Setenv("NO_SSL_VERIFY", "true")

	// Only attributes that have no env var are set in the provider block.
	logFile := filepath.Join(dir, "env-test.log")
	p := &ciphertrustProvider{}
	req := buildProviderConfigure(t,
		map[string]string{
			"log_file":  logFile,
			"log_level": "warn",
		},
		nil,
		nil,
	)

	client := runProviderConfigure(t, p, req)
	settingsVerify(t, p, client,
		cmURL, "env-user", "env-pass", "env-domain", "env-auth",
		55*time.Second,
		defaultAwsOperationTimeout, // no env var -- uses coded default
		defaultOciOperationTimeout, // no env var -- uses coded default
		66,
		true,
		logFile,
		hclog.LevelFromString("warn"),
	)
}

// TestUnit_Provider_SettingsHonoured_ConfigFile verifies that every provider
// attribute is taken from the ~/.ciphertrust/config file when neither
// environment variables nor provider block values are present. This test is
// skipped on Windows because the provider's permission check for the config
// file relies on Unix-style mode bits.
func TestUnit_Provider_SettingsHonoured_ConfigFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("config-file permission check uses Unix mode bits -- skipping on Windows")
	}

	cmURL := startMockCM(t)
	dir := t.TempDir()
	setHomeDir(t, dir)

	// Unset all env vars so the config file is the sole source.
	clearEnvVars(t,
		"CIPHERTRUST_ADDRESS", "CIPHERTRUST_USERNAME", "CIPHERTRUST_PASSWORD",
		"CIPHERTRUST_DOMAIN", "CIPHERTRUST_AUTH_DOMAIN",
		"REST_API_TIMEOUT", "CIPHERTRUST_REPLICATION_DELAY", "NO_SSL_VERIFY",
	)

	logFile := filepath.Join(dir, "cfg-test.log")

	cfgDir := filepath.Join(dir, ".ciphertrust")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatalf("create .ciphertrust dir: %v", err)
	}
	cfgLines := []string{
		"address = " + cmURL,
		"username = cfg-user",
		"password = cfg-pass",
		"domain = cfg-domain",
		"auth_domain = cfg-auth",
		"rest_api_timeout = 77",
		"aws_operation_timeout = 11",
		"oci_operation_timeout = 22",
		"replication_delay_ms = 33",
		"no_ssl_verify = true",
		"log_file = " + logFile,
		"log_level = warn",
	}
	cfgPath := filepath.Join(cfgDir, "config")
	if err := os.WriteFile(cfgPath, []byte(strings.Join(cfgLines, "\n")), 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	// Provider block is fully empty.
	p := &ciphertrustProvider{}
	req := buildProviderConfigure(t, nil, nil, nil)

	client := runProviderConfigure(t, p, req)
	settingsVerify(t, p, client,
		cmURL, "cfg-user", "cfg-pass", "cfg-domain", "cfg-auth",
		77*time.Second, 11, 22, 33, true, logFile,
		hclog.LevelFromString("warn"),
	)
}

// TestUnit_Provider_Cluster_IsClusteredTrue verifies that checkIsClustered sets
// client.IsClustered = true when the cluster endpoint reports more than one
// node. This matters because IsClustered gates the waitForReplication logic: if
// it is incorrectly always false, replication delays would never be observed
// even when replication_delay_ms is set.
func TestUnit_Provider_Cluster_IsClusteredTrue(t *testing.T) {
	dir := t.TempDir()
	setHomeDir(t, dir)
	clearEnvVars(t,
		"CIPHERTRUST_ADDRESS", "CIPHERTRUST_USERNAME", "CIPHERTRUST_PASSWORD",
		"CIPHERTRUST_DOMAIN", "CIPHERTRUST_AUTH_DOMAIN",
		"REST_API_TIMEOUT", "CIPHERTRUST_REPLICATION_DELAY", "NO_SSL_VERIFY",
	)

	// Start a mock server that reports a two-node cluster.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "auth/tokens"):
			_ = json.NewEncoder(w).Encode(map[string]string{
				"jwt":           "unit-test-fake-token",
				"refresh_token": "unit-test-fake-refresh",
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "cluster"):
			// nodeCount = 2 means the instance IS part of a multi-node cluster.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"nodeCount": 2})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	logFile := filepath.Join(dir, "cluster-test.log")
	p := &ciphertrustProvider{}
	req := buildProviderConfigure(t,
		map[string]string{
			"address":   srv.URL,
			"username":  "admin",
			"password":  "pass",
			"bootstrap": "no",
			"log_file":  logFile,
			"log_level": "off",
		},
		nil,
		map[string]bool{"no_ssl_verify": true},
	)

	client := runProviderConfigure(t, p, req)

	if !client.IsClustered {
		t.Error("IsClustered: want true for a two-node cluster response, got false")
	}
}

// TestUnit_Provider_Precedence_BlockOverridesEnv verifies that provider block
// values take precedence over environment variables for every attribute that
// supports both sources. Env vars are set to "env" values and the provider
// block is set to "block" values; the resulting client must reflect the block
// values.
func TestUnit_Provider_Precedence_BlockOverridesEnv(t *testing.T) {
	cmURL := startMockCM(t)
	dir := t.TempDir()
	setHomeDir(t, dir)

	// Set env vars to one set of values.
	t.Setenv("CIPHERTRUST_ADDRESS", cmURL) // same URL -- connectivity unchanged
	t.Setenv("CIPHERTRUST_USERNAME", "env-user")
	t.Setenv("CIPHERTRUST_PASSWORD", "env-pass")
	t.Setenv("CIPHERTRUST_DOMAIN", "env-domain")
	t.Setenv("CIPHERTRUST_AUTH_DOMAIN", "env-auth")
	t.Setenv("REST_API_TIMEOUT", "55")
	t.Setenv("CIPHERTRUST_REPLICATION_DELAY", "66")
	t.Setenv("NO_SSL_VERIFY", "true")

	// Provider block overrides with different values.
	logFile := filepath.Join(dir, "prec-test.log")
	p := &ciphertrustProvider{}
	req := buildProviderConfigure(t,
		map[string]string{
			"address":     cmURL,
			"username":    "block-user",
			"password":    "block-pass",
			"domain":      "block-domain",
			"auth_domain": "block-auth",
			"bootstrap":   "no",
			"log_file":    logFile,
			"log_level":   "info",
		},
		map[string]int64{
			"rest_api_timeout":      77,
			"aws_operation_timeout": 11,
			"oci_operation_timeout": 22,
			"replication_delay_ms":  33,
		},
		map[string]bool{
			"no_ssl_verify": true,
		},
	)

	client := runProviderConfigure(t, p, req)

	// Block values must win over env-var values.
	settingsVerify(t, p, client,
		cmURL, "block-user", "block-pass", "block-domain", "block-auth",
		77*time.Second, 11, 22, 33, true, logFile,
		hclog.LevelFromString("info"),
	)
}
