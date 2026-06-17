package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEProcessSet(t *testing.T) {
	name := "TestProcessSet-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_process_set" "process_set" {
  name = %q
  processes = [
    {
      signature=""
      directory="/home/testUser"
	  file="*"
    }
  ]
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_process_set.process_set", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_process_set" "process_set" {
  name = %q
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
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_process_set.process_set", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
