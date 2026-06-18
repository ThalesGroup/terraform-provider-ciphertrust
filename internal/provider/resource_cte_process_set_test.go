package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEProcessSet(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cte_process_set" "process_set" {
  name = "TestProcessSet"
  processes = [
    {
      signature=""
      directory="/home/testUser"
	  file="*"
    }
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_process_set.process_set", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "ciphertrust_cte_process_set" "process_set" {
  name = "TestProcessSet"
  processes = [
	{
      signature=""
      directory="/home/testUser"
      file="*"
    },
	{
      signature=""
      directory="/tmp"
      file="*"
    },
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_process_set.process_set", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
