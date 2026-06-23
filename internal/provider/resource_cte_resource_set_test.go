package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEResourceSet(t *testing.T) {
	name := "testResourceSet-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "resource_set" {
  name = %q
  resources = [
    {
      directory="/tmp"
      file="*"
	  hdfs=false
	  include_subfolders=false
    }
  ]
  type="Directory"
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_resource_set.resource_set", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "resource_set" {
  name = %q
  description = "Updated via TF"
  resources = [
    {
      directory="/tmp"
      file="*"
	  hdfs=false
	  include_subfolders=false
    },
	{
      directory="/home/testUser"
      file="*"
	  hdfs=false
	  include_subfolders=false
    }
  ]
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_resource_set.resource_set", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
