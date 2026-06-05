package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMRegToken(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}

output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}

resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify number of items
					//resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.reg_token", "items.#", "1"),
					// Verify first order item
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.quantity", "2"),
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.coffee.id", "1"),
					// Verify first coffee item has Computed attributes filled.
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.coffee.description", ""),
					// Verify dynamic values have any value set in the state.
					//resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "token"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "id"),
				),
			},
			// ImportState testing
			//{
			//	ResourceName:      "ciphertrust_cm_reg_token.reg_token",
			//	ImportState:       true,
			//	ImportStateVerify: true,
			// The last_updated attribute does not exist in the HashiCups
			// API, therefore there is no value for it during import.
			//	ImportStateVerifyIgnore: []string{"last_updated"},
			//},
			// Update and Read testing
			{
				Config: providerConfig + `
data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}
output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}
resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify first order item updated
					//resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "token"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// cmRegTokenOOBConfig is a registration token used by the out-of-band
// reconciliation tests (TFIN-293). max_clients is set so its drift can be
// observed by Read().
const cmRegTokenOOBConfig = `
data "ciphertrust_cm_local_ca_list" "oob_local_cas" {
  filters = {
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}

resource "ciphertrust_cm_reg_token" "oob_reg_token" {
  ca_id       = tolist(data.ciphertrust_cm_local_ca_list.oob_local_cas.cas)[0].id
  max_clients = 5
}
`

// TestResourceCMRegTokenOutOfBandDelete verifies that after a registration token
// is deleted out of band, Read() drops it from state and the next plan proposes
// to recreate it (TFIN-293).
func TestResourceCMRegTokenOutOfBandDelete(t *testing.T) {
	const tokenResource = "ciphertrust_cm_reg_token.oob_reg_token"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cmRegTokenOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(tokenResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[tokenResource]
						if !ok {
							return fmt.Errorf("%s not found in state", tokenResource)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Delete the token out of band, then refresh: Read must remove it
				// from state and propose recreate.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"tfin293-regtoken-oob-delete",
						common.URL_REG_TOKEN+"/"+capturedID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Recovery: re-apply to recreate the token so teardown is clean.
				Config: providerConfig + cmRegTokenOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(tokenResource, "id"),
				),
			},
		},
	})
}

// TestResourceCMRegTokenOutOfBandDrift verifies that an out-of-band modification
// of a managed attribute (max_clients) is surfaced as a plan diff after refresh
// (TFIN-293).
func TestResourceCMRegTokenOutOfBandDrift(t *testing.T) {
	const tokenResource = "ciphertrust_cm_reg_token.oob_reg_token"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cmRegTokenOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(tokenResource, "max_clients", "5"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[tokenResource]
						if !ok {
							return fmt.Errorf("%s not found in state", tokenResource)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_REG_TOKEN,
						[]byte(`{"max_clients":99}`),
						"id",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
