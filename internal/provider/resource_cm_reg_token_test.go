package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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

// TestResourceCMRegTokenReadDriftDetection verifies that the Read() function
// properly detects out-of-band deletion of a reg token on CipherTrust Manager.
func TestResourceCMRegTokenReadDriftDetection(t *testing.T) {
	var createdTokenID string

	// Helper to delete the reg token directly on CM (simulating out-of-band deletion)
	deleteTokenOutOfBand := func() {
		address := os.Getenv("CIPHERTRUST_ADDRESS")
		username := os.Getenv("CIPHERTRUST_USERNAME")
		password := os.Getenv("CIPHERTRUST_PASSWORD")
		if address == "" {
			address = "https://192.168.2.135"
			username = "admin"
			password = "ChangeIt01!"
		}
		domain := "root"
		client, err := common.NewClient(context.Background(), uuid.NewString(), &address, &domain, &domain, &username, &password, true, 180)
		if err != nil {
			t.Fatalf("Failed to create CM client for out-of-band deletion: %s", err)
		}
		url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_REG_TOKEN, createdTokenID)
		_, err = client.DeleteByID(context.Background(), "DELETE", createdTokenID, url, nil)
		if err != nil {
			t.Fatalf("Failed to delete reg token out-of-band: %s", err)
		}
	}

	config := testProviderConfig() + `
resource "ciphertrust_cm_reg_token" "drift_test" {
  lifetime    = "24h"
  max_clients = 3
  name_prefix = "tf-drift-test"
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the reg token
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.drift_test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.drift_test", "token"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.drift_test", "max_clients", "3"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.drift_test", "name_prefix", "tf-drift-test"),
					// Capture the ID for out-of-band deletion
					resource.TestCheckResourceAttrWith("ciphertrust_cm_reg_token.drift_test", "id", func(value string) error {
						createdTokenID = value
						return nil
					}),
				),
			},
			// Step 2: Delete the token out-of-band, then re-apply same config.
			// Terraform should detect the token is gone (via Read() returning 404)
			// and recreate it.
			{
				PreConfig: deleteTokenOutOfBand,
				Config:    config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.drift_test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.drift_test", "token"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
