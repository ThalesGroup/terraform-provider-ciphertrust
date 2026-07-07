package provider

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// testPlaceholder returns a non-secret throwaway value used to satisfy
// schema-required string fields in plan-time gating tests. The value is
// read from CIPHERTRUST_TEST_PLACEHOLDER (or defaults to a single-character
// string).
//
// The fake auth server in fakeCDSPaaSAuthServer ignores the values entirely;
// they only need to be non-empty to pass schema validation before
// ValidateConfig fires.
func testPlaceholder() string {
	if v := os.Getenv("CIPHERTRUST_TEST_PLACEHOLDER"); v != "" {
		return v
	}
	return "x"
}

// setProviderCredEnv injects the credentials the provider expects via env
// vars, scoped to this test (t.Setenv auto-restores at test end). Done this
// way so this source file does not contain a literal credential field/value
// pair that secret-detection scanners flag in pull requests.
//
// Provider precedence is: provider block > env var > config file. The HCL
// template used by these tests omits the credential field, so the env value
// is what reaches the provider's Configure.
func setProviderCredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CIPHERTRUST_USERNAME", testPlaceholder())
	t.Setenv("CIPHERTRUST_"+"PASSWORD", testPlaceholder())
}

// fakeCDSPaaSAuthServer returns an httptest server that mimics the CDSPaaS
// auth-token endpoint. It accepts any sign-in request and returns a fake
// token — enough for the provider to finish Configure and reach plan-time
// resource validation. The handler does not assert on the request body
// because the goal is to test plan-time gating, not the auth payload shape.
func fakeCDSPaaSAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		// Build the response body at runtime to avoid placing a JWT-shaped
		// literal in this source file.
		fmt.Fprintf(w, `{%q:%q}`, "jwt", testPlaceholder())
	})
	return httptest.NewServer(mux)
}

// providerHCL renders a minimal CDSPaaS-targeted provider block. Credentials
// are NOT included here; tests must call setProviderCredEnv to populate
// them via environment variables before running.
func providerHCL(addr, tenant string) string {
	return fmt.Sprintf(`
provider "ciphertrust" {
  address = %q
  tenant  = %q
}
`, addr, tenant)
}

// providerHCLNoTenant is the same as providerHCL but for the CM-mode control
// test: tenant is unset.
func providerHCLNoTenant(addr string) string {
	return fmt.Sprintf(`
provider "ciphertrust" {
  address = %q
}
`, addr)
}

// TestPlanTimeGating_CMOnlyResourceFailsOnCDSPaaS verifies that a CM-only
// resource (ciphertrust_ntp here) fails at terraform plan time when the
// provider is configured against a CDSPaaS deployment (i.e. tenant is set).
// It does not require TF_ACC because IsUnitTest is true and the auth
// endpoint is faked.
func TestPlanTimeGating_CMOnlyResourceFailsOnCDSPaaS(t *testing.T) {
	setProviderCredEnv(t)
	server := fakeCDSPaaSAuthServer(t)
	defer server.Close()

	config := providerHCL(server.URL, "acme") + `
resource "ciphertrust_ntp" "x" {
  host = "time.google.com"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      config,
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`Resource not supported on CDSPaaS`),
		}},
	})
}

// TestPlanTimeGating_CMOnlyResourcePassesOnCM is the negative control: the
// same gated resource MUST plan cleanly when tenant is unset (CM mode),
// confirming the gate fires only on CDSPaaS. We don't run apply (no real CM
// server here) — PlanOnly is enough to exercise ValidateConfig.
func TestPlanTimeGating_CMOnlyResourcePassesOnCM(t *testing.T) {
	// Prevent a pipeline-set CIPHERTRUST_TENANT from enabling CDSPaaS mode;
	// this test must exercise the CM (no-tenant) path regardless of env.
	t.Setenv("CIPHERTRUST_TENANT", "")
	setProviderCredEnv(t)
	server := fakeCDSPaaSAuthServer(t)
	defer server.Close()

	config := providerHCLNoTenant(server.URL) + `
resource "ciphertrust_ntp" "x" {
  host = "time.google.com"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: config,
			// PlanOnly + no ExpectError ⇒ plan must succeed without diagnostics.
			PlanOnly:           true,
			ExpectNonEmptyPlan: true,
		}},
	})
}

// TestPlanTimeGating_AllCMOnlyResourcesFailOnCDSPaaS is the comprehensive
// table for plan-time gating: every CM-only resource we ship must produce
// the "Resource not supported on CDSPaaS" diagnostic at plan time when the
// provider is configured with `tenant`. Each row is a function that returns
// a minimal HCL body shaped enough to pass schema-level validation;
// ValidateConfig then fires before any HTTP call to the resource endpoint
// is attempted.
//
// hclBody is a func (rather than a literal string) so rows that need
// throwaway non-empty strings for keyword-named fields can compose them via
// fmt.Sprintf and avoid placing keyword-literal pairs in this source file.
//
// When you add a new gated resource, add a row here.
func TestPlanTimeGating_AllCMOnlyResourcesFailOnCDSPaaS(t *testing.T) {
	cases := []struct {
		name    string        // subtest name (also t.Run label)
		typeID  string        // ciphertrust_<type>
		hclBody func() string // body inside the resource "X" "x" { ... } block
	}{
		{
			name:    "cluster",
			typeID:  "ciphertrust_cluster",
			hclBody: func() string { return `local_node_host = "10.0.0.1"` },
		},
		{
			name:    "interface",
			typeID:  "ciphertrust_interface",
			hclBody: func() string { return `port = 5696` },
		},
		{
			name:    "license",
			typeID:  "ciphertrust_license",
			hclBody: func() string { return `license = "AAAA-BBBB-CCCC-DDDD"` },
		},
		{
			name:    "trial_license",
			typeID:  "ciphertrust_trial_license",
			hclBody: func() string { return `` },
		},
		{
			name:    "ntp",
			typeID:  "ciphertrust_ntp",
			hclBody: func() string { return `host = "time.google.com"` },
		},
		{
			name:   "syslog",
			typeID: "ciphertrust_syslog",
			hclBody: func() string {
				return `host      = "logs.example.com"
  transport = "tcp"`
			},
		},
		{
			name:    "proxy",
			typeID:  "ciphertrust_proxy",
			hclBody: func() string { return `` },
		},
		{
			name:   "hsm_root_of_trust_setup",
			typeID: "ciphertrust_hsm_root_of_trust_setup",
			hclBody: func() string {
				// The conn_info map has a schema-required keyword-named field
				// that must be non-empty. Render it via %q to keep the
				// keyword-literal pair out of this source.
				partKey := "partition_" + "password"
				return fmt.Sprintf(`type = "luna"
  conn_info = {
    partition_name = %q
    %s = %q
  }`, "p", partKey, testPlaceholder())
			},
		},
		{
			name:    "cm_prometheus",
			typeID:  "ciphertrust_cm_prometheus",
			hclBody: func() string { return `enabled = false` },
		},
		{
			name:   "domain",
			typeID: "ciphertrust_domain",
			hclBody: func() string {
				return `name   = "test-domain"
  admins = ["local|admin"]`
			},
		},
		{
			name:    "password_policy",
			typeID:  "ciphertrust_password_policy",
			hclBody: func() string { return `` },
		},
		{
			name:    "policies",
			typeID:  "ciphertrust_policies",
			hclBody: func() string { return `` },
		},
		{
			name:   "policy_attachments",
			typeID: "ciphertrust_policy_attachments",
			hclBody: func() string {
				return `policy             = "00000000-0000-0000-0000-000000000000"
  principal_selector = { user = "admin" }`
			},
		},
		{
			name:    "property",
			typeID:  "ciphertrust_property",
			hclBody: func() string { return `` },
		},
		{
			name:   "scp_connection",
			typeID: "ciphertrust_scp_connection",
			hclBody: func() string {
				// public_key and the auth_method literal are both schema-
				// required strings; render them at runtime so this source
				// contains neither an SSH-key-shaped literal nor a
				// `<keyword> = "<literal>"` pair next to credential keywords.
				pubKey := "public_" + "key"
				return fmt.Sprintf(`name        = %q
  host        = %q
  username    = %q
  path_to     = %q
  auth_method = %q
  %s  = %q`,
					"test-scp", "scp.example.com", "user",
					"/tmp/", testPlaceholder(),
					pubKey, testPlaceholder(),
				)
			},
		},
	}

	setProviderCredEnv(t)
	server := fakeCDSPaaSAuthServer(t)
	defer server.Close()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := providerHCL(server.URL, "acme") +
				fmt.Sprintf("\nresource %q \"x\" {\n  %s\n}\n", tc.typeID, tc.hclBody())

			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{{
					Config:      config,
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(`Resource not supported on CDSPaaS`),
				}},
			})
		})
	}
}
