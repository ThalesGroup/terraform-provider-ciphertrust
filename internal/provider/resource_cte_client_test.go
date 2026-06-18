package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEClient(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create testing
			{
				Config: providerConfig + `
resource "ciphertrust_cte_client" "client" {
  name                     = "testClient1"
  password_creation_method = "GENERATE"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_client.client", "id"),
				),
			},

			// Step 2: Update and read testing
			{
				Config: providerConfig + `
resource "ciphertrust_cte_client" "client" {
  name                     = "testClient1"
  password_creation_method = "GENERATE"
  description              = "Updated via TF"
  client_locked            = true
  registration_allowed     = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_client.client", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
