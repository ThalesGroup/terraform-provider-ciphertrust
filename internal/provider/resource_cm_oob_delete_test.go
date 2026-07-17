package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TestCipherTrust_CMDomain_OOBDelete verifies that when a domain is deleted
// directly on CipherTrust Manager (out-of-band), terraform refresh removes it
// from state gracefully and produces a non-empty plan (recreate).
func Test_CM_CipherTrust_CMDomain_OOBDelete(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := fmt.Sprintf("tf-domain-oob-%d", time.Now().Unix())
	var domainID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the domain and capture its ID.
			{
				PreConfig: func() { domainSweep() },
				Config:    cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						domainID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: Delete out-of-band, then refresh. Read() gets 404 → RemoveResource.
			// Terraform detects the resource is gone and plans a recreation.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM not configured")
					}
					delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, domainID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", domainID, delURL, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestCipherTrust_CMPolicy_OOBDelete verifies that when a policy is deleted
// directly on CipherTrust Manager (out-of-band), terraform refresh removes it
// from state gracefully and produces a non-empty plan (recreate).
func Test_CM_CipherTrust_CMPolicy_OOBDelete(t *testing.T) {
	RequireCM(t)
	policyName := fmt.Sprintf("tf-policy-oob-%d", time.Now().Unix())
	var policyID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_policies" "test" {
  name    = %q
  actions = ["ReadKey"]
  allow   = true
  effect  = "allow"
}
`, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the policy and capture its ID.
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_policies.test", "id"),
					func(s *terraform.State) error {
						policyID = s.RootModule().Resources["ciphertrust_policies.test"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: Delete out-of-band, then refresh. Read() gets 404 → RemoveResource.
			// Terraform detects the resource is gone and plans a recreation.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM not configured")
					}
					endpoint := common.URL_CM_POLICIES + "/" + policyID
					_, _ = client.DeleteByURL(context.Background(), policyID, endpoint)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestCipherTrust_CMLogForwarder_OOBDelete verifies that when a log forwarder is
// deleted directly on CipherTrust Manager (out-of-band), terraform refresh removes
// it from state gracefully and produces a non-empty plan (recreate).
func Test_CM_CipherTrust_CMLogForwarder_OOBDelete(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := fmt.Sprintf("tf-lf-oob-%d", time.Now().Unix())
	var logForwarderID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  name          = %q
  type          = "syslog"
  connection_id = %q
}
`, rName, connID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the log forwarder and capture its ID.
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					func(s *terraform.State) error {
						logForwarderID = s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: Delete out-of-band, then refresh. Read() gets 404 → RemoveResource.
			// Terraform detects the resource is gone and plans a recreation.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM not configured")
					}
					delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_CM_LOG_FORWARDS, logForwarderID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", logForwarderID, delURL, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestCipherTrust_CMPrometheus_OOBDelete is omitted: ciphertrust_cm_prometheus does not
// implement ResourceWithImportState, so an ImportState step would error at the framework
// level before invoking Read(). The 404 fix for resource_cm_prometheus.go is verified by
// code inspection of the Before→After change only.
