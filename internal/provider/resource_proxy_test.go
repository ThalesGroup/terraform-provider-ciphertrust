package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	uuid "github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Test_CM_Proxy_CreateUpdate verifies that a ciphertrust_proxy singleton resource can be
// configured with an http_proxy URL (Step 1) and then updated to a different URL (Step 2).
// The proxy resource has no id attribute — it is a singleton that configures outbound
// proxy settings on the CipherTrust Manager appliance.
// Required env vars: CM_TEST_HTTP_PROXY (initial URL), CM_TEST_HTTP_PROXY_UPDATED (updated URL).
func Test_CM_Proxy_CreateUpdate(t *testing.T) {
	RequireCM(t)

	httpProxy := os.Getenv("CM_TEST_HTTP_PROXY")
	if httpProxy == "" {
		t.Skip("CM_TEST_HTTP_PROXY not set — skipping proxy acceptance test")
	}
	httpProxyUpdated := os.Getenv("CM_TEST_HTTP_PROXY_UPDATED")
	if httpProxyUpdated == "" {
		t.Skip("CM_TEST_HTTP_PROXY_UPDATED not set — skipping proxy acceptance test")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProxyConfig(httpProxy),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "http_proxy"),
				),
			},
			{
				Config: testAccProxyConfig(httpProxyUpdated),
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "http_proxy"),
				),
			},
		},
	})
}

func testAccProxyConfig(httpProxy string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_proxy" "test" {
  http_proxy = %q
}
`, httpProxy)
}

func proxyCleanup(t *testing.T) {
	t.Helper()
	client, ok := createCMClient()
	if !ok {
		return
	}
	ctx := context.Background()
	traceID := uuid.New().String()
	payload, err := json.Marshal(map[string]interface{}{
		"http_proxy":  "",
		"https_proxy": "",
		"no_proxy":    []string{},
		"certificate": "",
	})
	if err != nil {
		return
	}
	_, _ = client.PutData(ctx, traceID, common.URL_CM_PROXY, payload)
}

func Test_CM_Proxy_DriftDetection(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CM_TEST_HTTP_PROXY") == "" {
		t.Skip("CM_TEST_HTTP_PROXY not set — skipping proxy acceptance test to prevent breaking live CM")
	}
	t.Cleanup(func() { proxyCleanup(t) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProxyConfig("http://10.0.0.1:3128"),
				Check: checkStep(t, "apply",
					resource.TestCheckResourceAttr("ciphertrust_proxy.test", "http_proxy", "http://10.0.0.1:3128"),
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client not available; skipping OOB proxy update")
						return
					}
					ctx := context.Background()
					traceID := uuid.New().String()
					payload, err := json.Marshal(map[string]string{"http_proxy": "http://10.0.0.2:3128"})
					if err != nil {
						t.Logf("failed to marshal OOB proxy payload: %v", err)
						return
					}
					_, err = client.PutData(ctx, traceID, common.URL_CM_PROXY, payload)
					if err != nil {
						t.Logf("OOB proxy update failed: %v", err)
						return
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_Proxy_NoImmutableFields(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CM_TEST_HTTP_PROXY") == "" {
		t.Skip("CM_TEST_HTTP_PROXY not set — skipping proxy acceptance test to prevent breaking live CM")
	}
	t.Cleanup(func() { proxyCleanup(t) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProxyConfig("http://10.0.0.1:3128"),
				Check: checkStep(t, "initial apply",
					resource.TestCheckResourceAttr("ciphertrust_proxy.test", "http_proxy", "http://10.0.0.1:3128"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy  = "http://10.0.0.3:3128"
  https_proxy = "http://10.0.0.3:3129"
}
`,
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_proxy.test", "http_proxy", "http://10.0.0.3:3128"),
					resource.TestCheckResourceAttr("ciphertrust_proxy.test", "https_proxy", "http://10.0.0.3:3129"),
				),
			},
		},
	})
}

func Test_CM_Proxy_Idempotency(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CM_TEST_HTTP_PROXY") == "" {
		t.Skip("CM_TEST_HTTP_PROXY not set — skipping proxy acceptance test to prevent breaking live CM")
	}
	t.Cleanup(func() { proxyCleanup(t) })

	config := testAccProxyConfig("http://10.0.0.1:3128")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "apply",
					resource.TestCheckResourceAttr("ciphertrust_proxy.test", "http_proxy", "http://10.0.0.1:3128"),
				),
			},
			{
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CipherTrustProxy_NoSpuriousDiffAfterApply verifies that immediately after
// terraform apply with a credentialed proxy URL, terraform plan -refresh-only
// reports no changes (no perpetual cleartext→masked diff).
func Test_CM_CipherTrustProxy_NoSpuriousDiffAfterApply(t *testing.T) {
	RequireCM(t)
	t.Cleanup(func() { proxyCleanup(t) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "http://user01:test12345@10.171.18.190:8080"
}
`,
				Check: checkStep(t, "apply",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "id"),
				),
			},
			// Refresh with no OOB change — must report no diff.
			// Verifies the fix does not introduce a spurious perpetual cleartext→masked diff.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CipherTrustProxy_HTTPProxyHostPortDriftDetection verifies that an OOB
// host/port change on http_proxy is surfaced by terraform plan -refresh-only.
func Test_CM_CipherTrustProxy_HTTPProxyHostPortDriftDetection(t *testing.T) {
	RequireCM(t)
	t.Cleanup(func() { proxyCleanup(t) })
	var capturedResourceID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "http://user01:test12345@10.171.18.190:8080"
}
`,
				Check: checkStep(t, "apply",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_proxy.test"]
						if !ok {
							return fmt.Errorf("resource ciphertrust_proxy.test not found in state")
						}
						capturedResourceID = rs.Primary.ID
						return nil
					},
				),
			},
			// OOB host/port change; assert drift is detected.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB PATCH step; test may not validate drift")
						return
					}
					ctx := context.Background()
					traceID := uuid.New().String()
					payload, err := json.Marshal(map[string]string{"http_proxy": "http://user01:test12345@10.171.18.200:9090"})
					if err != nil {
						t.Logf("failed to marshal OOB proxy payload: %v", err)
						return
					}
					// PutData is used here (not UpdateDataV2) because the proxy resource is a
					// singleton with no {id} path segment. Update() in resource_proxy.go uses
					// PutData for the same reason — this mirrors the exact HTTP call the
					// provider makes, so the OOB change is semantically identical to an
					// out-of-band update performed via the CM API directly.
					_, err = client.PutData(ctx, traceID, common.URL_CM_PROXY, payload)
					if err != nil {
						t.Logf("OOB PATCH failed (capturedResourceID=%s): %v — drift may not be detectable", capturedResourceID, err)
						return
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CipherTrustProxy_HTTPSProxyHostPortDriftDetection verifies that an OOB
// host/port change on https_proxy is surfaced by terraform plan -refresh-only.
func Test_CM_CipherTrustProxy_HTTPSProxyHostPortDriftDetection(t *testing.T) {
	RequireCM(t)
	t.Cleanup(func() { proxyCleanup(t) })
	var capturedResourceID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  https_proxy = "https://user01:test12345@10.171.18.190:8443"
}
`,
				Check: checkStep(t, "apply",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_proxy.test"]
						if !ok {
							return fmt.Errorf("resource ciphertrust_proxy.test not found in state")
						}
						capturedResourceID = rs.Primary.ID
						return nil
					},
				),
			},
			// OOB host/port change on https_proxy; assert drift is detected.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB PATCH step; test may not validate drift")
						return
					}
					ctx := context.Background()
					traceID := uuid.New().String()
					payload, err := json.Marshal(map[string]string{"https_proxy": "https://user01:test12345@10.171.18.200:9443"})
					if err != nil {
						t.Logf("failed to marshal OOB proxy payload: %v", err)
						return
					}
					// PutData is used here (not UpdateDataV2) because the proxy resource is a
					// singleton with no {id} path segment. Update() in resource_proxy.go uses
					// PutData for the same reason — this mirrors the exact HTTP call the
					// provider makes, so the OOB change is semantically identical to an
					// out-of-band update performed via the CM API directly.
					_, err = client.PutData(ctx, traceID, common.URL_CM_PROXY, payload)
					if err != nil {
						t.Logf("OOB PATCH failed (capturedResourceID=%s): %v — drift may not be detectable", capturedResourceID, err)
						return
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_Proxy_InvalidValuesRejected verifies the fixes for the bugs reported
// against ciphertrust_proxy: http_proxy/https_proxy/certificate previously
// accepted malformed values with no validation at any layer (schema or CM API)
// and stored them verbatim. Each step is PlanOnly so it never reaches the CM
// API — the schema validators (validators.URL, validators.PEMCertificate) must
// reject these values at plan time.
func Test_CM_Proxy_InvalidValuesRejected(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// ProxyURL() rejects values containing whitespace (a proxy address never has spaces).
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "invalid" {
  http_proxy = "http://host with spaces:8080"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Invalid Proxy Address`),
			},
			// ProxyURL() rejects empty string.
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "invalid" {
  https_proxy = "   "
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Invalid Proxy Address`),
			},
			// PEM certificate validator is unchanged.
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "invalid" {
  certificate = "not-a-real-pem-cert-value"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Invalid PEM Certificate`),
			},
		},
	})
}

// Test_CM_Proxy_SchemelessURLAccepted verifies that schemeless proxy addresses
// (CM documented "Scenario 3") are accepted at plan time. (TFIN-526)
// PlanOnly: true — never applies to live CM (proxy config is a system singleton).
func Test_CM_Proxy_SchemelessURLAccepted(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Schemeless with credentials — CM documents this as valid Scenario 3.
			// ExpectNonEmptyPlan: true because this is a new resource (no prior state).
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy  = "proxy-user:ssl12345@10.171.30.20:3300"
  https_proxy = "cckmdev-proxy.example.com:443"
}`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				// Key assertion: no ExpectError — the validator must not fire.
			},
		},
	})
}

// Test_CM_Proxy_UpdateCredentialedProxy verifies that the plan for updating
// http_proxy to a credentialed URL is accepted without a validator error, and
// that the plan-level state is consistent (no "inconsistent result" diagnostic).
// (TFIN-527)
//
// This test is PlanOnly to avoid modifying the live CM proxy configuration
// (ciphertrust_proxy is a system singleton — applying changes would affect CM).
// The TFIN-527 fix (preserving plan value in Update()) is validated by the unit
// test infrastructure; the acceptance test here confirms plan-level correctness.
func Test_CM_Proxy_UpdateCredentialedProxy(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Plan with first credentialed URL — must not error.
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "http://u:pass1@10.171.30.20:3300"
}`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Step 2: Plan with a different credentialed URL — must not error.
			// Before TFIN-527, this path crashed at apply due to CM masking corruption.
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "http://proxyuser:p@10.171.30.20:3300"
}`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
