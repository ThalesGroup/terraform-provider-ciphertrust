package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMDomain(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name = "%s"
  admins = ["admin"]
  allow_user_management = false
  meta_data = {
      "abc": "xyz"
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.testDomain", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.testDomain", "name", rName),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name = "%s"
  admins = ["admin"]
  allow_user_management = false
  meta_data = {
      "abc": "xyz",
	  "color": "blue"
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.testDomain", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.testDomain", "name", rName),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestCMDomainNameImmutable verifies that attempting to rename a domain after
// creation produces a clear, actionable plan-time error rather than silent
// state drift.
func TestCMDomainNameImmutable(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.testDomain", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.testDomain", "name", rName),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name   = %q
  admins = ["admin"]
}
`, rName+"-renamed"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// TestAccCMDomain_drift verifies that Read() correctly detects out-of-band
// changes to allow_user_management and meta_data, enabling Terraform drift
// detection for ciphertrust_domain resources.
func TestAccCMDomain_drift(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	domainConfig := func(allowUserMgmt bool, metaVal string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name                 = %q
  admins               = ["admin"]
  allow_user_management = %t
  meta_data            = { "key" = %q }
}
`, rName, allowUserMgmt, metaVal)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create domain, capture ID for OOB operations.
			{
				Config: domainConfig(false, "original"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "allow_user_management", "false"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.key", "original"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: OOB patch allow_user_management and meta_data; then refresh to
			// verify Read() surfaces both changes as drift.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("Skipping drift test: CM client could not be created")
					}
					patch := map[string]interface{}{
						"allow_user_management": true,
						"meta":                 map[string]string{"key": "modified"},
					}
					payload, err := json.Marshal(patch)
					if err != nil {
						t.Fatalf("failed to marshal drift patch: %s", err)
					}
					if _, err := client.UpdateData(context.Background(), capturedID, common.URL_DOMAIN, payload, "updatedAt"); err != nil {
						t.Skipf("OOB patch failed (environment may lack permission): %s", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			// Step 3: re-apply original config — confirms Update() corrects the drift.
			{
				Config: domainConfig(false, "original"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "allow_user_management", "false"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.key", "original"),
				),
			},
			// Step 4: verify no spurious drift on a clean plan.
			{
				Config:             domainConfig(false, "original"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCMDomain_deleteOOB verifies that when a domain is deleted out-of-band,
// Read() returns a 404 and removes the resource from state cleanly so that
// terraform plan shows a re-create rather than a hard error.
func TestAccCMDomain_deleteOOB(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-oob-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	domainConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create domain, capture ID for OOB deletion.
			{
				Config: domainConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: delete the domain OOB, then refresh — Read() must detect 404
			// and remove from state; plan shows re-create (ExpectNonEmptyPlan: true).
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("Skipping OOB deletion test: CM client could not be created")
					}
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, capturedID)
					if _, err := client.DeleteByID(context.Background(), "DELETE", capturedID, url, nil); err != nil {
						t.Fatalf("OOB deletion failed: %s", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMDomain_updateUsesID verifies that Update() sends PATCH /v1/domains/{uuid}
// (not /v1/domains/{name}) by confirming that a change to meta_data is applied
// correctly end-to-end. The UUID-path fix is exercised because a name-based path
// would 404 and UpdateData would return an error.
func TestAccCMDomain_updateUsesID(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-upd-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	domainConfig := func(metaVal string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = ["admin"]
  meta_data = { "key" = %q }
}
`, rName, metaVal)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with meta_data.key = "before".
			{
				Config: domainConfig("before"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.key", "before"),
				),
			},
			// Step 2: update meta_data — confirms PATCH /v1/domains/{uuid} works.
			{
				Config: domainConfig("after"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.key", "after"),
				),
			},
			// Step 3: assert no spurious drift after the update.
			{
				Config:             domainConfig("after"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
