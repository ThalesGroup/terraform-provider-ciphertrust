package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEClient(t *testing.T) {
	name := "testClient1-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  password_creation_method = "GENERATE"
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_client.client", "id"),
				),
			},

			// Step 2: Update and read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  password_creation_method = "GENERATE"
  description              = "Updated via TF"
  client_locked            = true
  registration_allowed     = true
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_client.client", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
