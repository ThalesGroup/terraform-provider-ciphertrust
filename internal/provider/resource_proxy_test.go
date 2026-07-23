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

// Test_CM_Proxy_DriftDetection documents that after the TFIN-439 fix, OOB host/port changes
// to http_proxy are no longer detectable (deliberate regression — see plan change summary).
// Read() no longer consults the CM GET response for http_proxy/https_proxy; state retains
// the last-applied plaintext unconditionally.
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
				// Post-fix: Read() no longer reads http_proxy from CM response — OOB host change is invisible.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
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

// Test_CM_Proxy_InvalidHTTPProxy verifies that a malformed http_proxy value is rejected
// at plan time by proxyURLValidator before any API call is made.
func Test_CM_Proxy_InvalidHTTPProxy(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "totally_not_a_url###garbage"
}
`,
				ExpectError: regexp.MustCompile("Invalid Proxy URL"),
			},
		},
	})
}

// Test_CM_Proxy_InvalidHTTPSProxy verifies that a malformed https_proxy value is rejected
// at plan time by proxyURLValidator before any API call is made.
func Test_CM_Proxy_InvalidHTTPSProxy(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  https_proxy = "not_a_valid_url_at_all!!!"
}
`,
				ExpectError: regexp.MustCompile("Invalid Proxy URL"),
			},
		},
	})
}

// Test_CM_Proxy_ValidCredentialedURL verifies that a credentialed proxy URL passes validation,
// is accepted by CM, and the resource id is set in state after apply.
func Test_CM_Proxy_ValidCredentialedURL(t *testing.T) {
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
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "id"),
				),
			},
		},
	})
}

// Test_CM_Proxy_PasswordOnlyOOBNoDrift verifies that a password-only OOB change to http_proxy
// produces no Terraform plan diff (TFIN-439 known limitation — deliberate write-only behavior).
func Test_CM_Proxy_PasswordOnlyOOBNoDrift(t *testing.T) {
	RequireCM(t)
	t.Cleanup(func() { proxyCleanup(t) })

	var capturedID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_proxy" "test" {
  http_proxy = "http://user01:test12345@10.171.18.190:8080"
}
`,
				Check: func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources["ciphertrust_proxy.test"]
					if ok {
						capturedID = rs.Primary.ID
					}
					return nil
				},
			},
			{
				PreConfig: func() {
					ctx := context.Background()
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB step")
						return
					}
					traceID := uuid.New().String()
					_ = capturedID
					payload, err := json.Marshal(map[string]interface{}{
						"http_proxy": "http://user01:differentpass999@10.171.18.190:8080",
					})
					if err != nil {
						t.Logf("failed to marshal OOB payload: %v", err)
						return
					}
					_, err = client.PutData(ctx, traceID, common.URL_CM_PROXY, payload)
					if err != nil {
						t.Logf("OOB PATCH failed: %v", err)
						return
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Proxy_HostPortOOBNoDrift documents that after the TFIN-439 fix, host/port OOB changes
// are also undetectable (deliberate regression from pre-fix behavior — see plan change summary).
func Test_CM_Proxy_HostPortOOBNoDrift(t *testing.T) {
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
				Check: checkStep(t, "initial apply",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "id"),
				),
			},
			{
				PreConfig: func() {
					ctx := context.Background()
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB step")
						return
					}
					traceID := uuid.New().String()
					payload, err := json.Marshal(map[string]interface{}{
						"http_proxy": "http://user01:differentpass999@10.171.18.199:9090",
					})
					if err != nil {
						t.Logf("failed to marshal OOB payload: %v", err)
						return
					}
					_, err = client.PutData(ctx, traceID, common.URL_CM_PROXY, payload)
					if err != nil {
						t.Logf("OOB PATCH failed: %v", err)
						return
					}
				},
				// Post-fix: Read() no longer consults CM response for http_proxy — drift is invisible.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
			{
				PreConfig: func() {
					// Restore original value to avoid contaminating other tests.
					ctx := context.Background()
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping restore step")
						return
					}
					traceID := uuid.New().String()
					payload, err := json.Marshal(map[string]interface{}{
						"http_proxy": "http://user01:test12345@10.171.18.190:8080",
					})
					if err != nil {
						t.Logf("failed to marshal restore payload: %v", err)
						return
					}
					_, err = client.PutData(ctx, traceID, common.URL_CM_PROXY, payload)
					if err != nil {
						t.Logf("restore OOB PATCH failed: %v", err)
						return
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
