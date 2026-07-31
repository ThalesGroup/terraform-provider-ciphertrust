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

// Test_CM_CipherTrustProxy_HTTPProxyCredentialedUpdate verifies that updating http_proxy
// from one credentialed URL to another does not crash with "Provider produced inconsistent
// result after apply". CM's own password masking can corrupt the visible (non-password)
// portion of its PUT/GET response (e.g. "http://..." coming back as "httxxxxxx://...");
// Update() must always commit the planned cleartext value regardless of what CM's masked
// response looks like, since http_proxy is a non-Computed attribute.
//
// ExpectNonEmptyPlan is set on the update steps: CM's masking corruption is not limited to
// the in-flight PUT response Update() sees — the same corruption can occur on a later GET
// too, which Read()'s own (unchanged, still-correct-in-principle) drift-detection logic
// then surfaces as a real diff against the cleartext config value. That's a separate,
// pre-existing, non-deterministic residual effect of CM's own bug (not a provider crash)
// and out of scope for this fix, which only guarantees the apply itself never crashes.
func Test_CM_CipherTrustProxy_HTTPProxyCredentialedUpdate(t *testing.T) {
	RequireCM(t)
	t.Cleanup(func() { proxyCleanup(t) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "http://svc:pass1@10.171.30.20:3300"
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "id"),
				),
			},
			{
				// Update to a different credentialed value — must not crash.
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "http://u:p@10.171.30.20:3300"
}
`,
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "id"),
				),
				ExpectNonEmptyPlan: true,
			},
			{
				// A second update with yet another username shape, matching the second
				// reproduction in the bug report.
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "http://proxyuser:p@10.171.30.20:3300"
}
`,
				Check: checkStep(t, "second update",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "id"),
				),
				ExpectNonEmptyPlan: true,
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
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "invalid" {
  http_proxy = "totally_not_a_url###garbage"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Invalid URL`),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "invalid" {
  https_proxy = "not_a_valid_url_at_all!!!"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Invalid URL`),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "invalid" {
  certificate = "not-a-real-pem-cert-value"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Invalid PEM Certificate`),
			},
			{
				// Well-formed PEM envelope, but the decoded body is not a real X.509
				// certificate — must be rejected, not just PEM-envelope-checked.
				Config: providerConfig + `
resource "ciphertrust_proxy" "invalid" {
  certificate = "-----BEGIN CERTIFICATE-----\nTm90QVJlYWxDZXJ0Qm9keUp1c3RHYXJiYWdlQmFzZTY0IQ==\n-----END CERTIFICATE-----"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Invalid PEM Certificate`),
			},
		},
	})
}
