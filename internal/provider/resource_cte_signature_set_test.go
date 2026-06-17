package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTESignatureSet(t *testing.T) {
	name := "testSignSet-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_signature_set" "signature_set" {
  name = %q
  source_list = [
    "/usr/bin",
    "/usr/sbin"
  ]
  type = "Application"
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_signature_set.signature_set", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_signature_set" "signature_set" {
  name = %q
  description = "Updated via TF"
  source_list = [
    "/usr/bin"
  ]
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_signature_set.signature_set", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
