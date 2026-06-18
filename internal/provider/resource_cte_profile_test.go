package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEProfile(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create
			{
				Config: providerConfig + `
resource "ciphertrust_cte_profile" "profile" {
  name        = "testProfile1"
  description = "Initial profile"

  concise_logging = true
  connect_timeout = 10

  cache_settings = {
    max_files = 500
    max_space = 200
  }

  file_settings = {
    allow_purge   = true
    file_threshold = "ERROR"
    max_file_size = 100000
    max_old_files = 5
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_profile.profile", "id"),
				),
			},

			// Step 2: Update
			{
				Config: providerConfig + `
resource "ciphertrust_cte_profile" "profile" {
  name        = "testProfile1"
  description = "Updated profile"

  concise_logging = false
  connect_timeout = 20

  cache_settings = {
    max_files = 800
    max_space = 300
  }

  file_settings = {
    allow_purge   = false
    file_threshold = "ERROR"
    max_file_size = 200000
    max_old_files = 10
  }

  duplicate_settings = {
    suppress_interval  = 10
    suppress_threshold = 5
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_profile.profile", "id"),
				),
			},
		},
		// Delete testing automatically occurs in TestCase
	})
}
