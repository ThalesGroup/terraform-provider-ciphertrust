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

func TestAccCipherTrustCMDomain_basic(t *testing.T) {
	RequireCM(t)
	rName := "tf-test-domain-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "updated_at"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.#", "1"),
				),
			},
			{
				// Verify Read() returns the same values — no drift after create.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin", "admin2"]
}
`, rName),
				Check: checkStep(t, "update admins",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.#", "2"),
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
				),
			},
		},
	})
}

func TestAccCipherTrustCMDomain_outOfBandDelete(t *testing.T) {
	RequireCM(t)
	rName := "tf-test-oob-delete-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band delete via CM client, then refresh.
				// Expected: Read() emits a warning, retains resource in state.
				// Plan shows recreation diff (ExpectNonEmptyPlan: true).
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					ctx := context.Background()
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, capturedID)
					_, _ = client.DeleteByID(ctx, "DELETE", capturedID, url, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCipherTrustCMDomain_driftDetection(t *testing.T) {
	RequireCM(t)
	rName := "tf-test-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name                 = %q
  admins               = ["admin"]
  allow_user_management = false
}
`, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "allow_user_management", "false"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band change allow_user_management to true, then refresh.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					ctx := context.Background()
					patchPayload, _ := json.Marshal(map[string]interface{}{"allow_user_management": true})
					_, _ = client.UpdateData(ctx, capturedID, common.URL_DOMAIN, patchPayload, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCipherTrustCMDomain_metaDrift(t *testing.T) {
	RequireCM(t)
	rName := "tf-test-meta-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = ["admin"]
  meta_data = { env = "test" }
}
`, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.env", "test"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band change meta out-of-band, then refresh.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					ctx := context.Background()
					patchPayload, _ := json.Marshal(map[string]interface{}{"meta": map[string]string{"env": "changed"}})
					_, _ = client.UpdateData(ctx, capturedID, common.URL_DOMAIN, patchPayload, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
