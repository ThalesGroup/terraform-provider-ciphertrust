package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMNTP(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "ntp_server_1" {
  host = "time1.google.com"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.ntp_server_1", "host", "time1.google.com"),
				),
			},
			{
				// Update test - this will trigger a replace (delete + create) due to RequiresReplace
				Config: providerConfig + `
resource "ciphertrust_ntp" "ntp_server_1" {
  host = "time2.google.com"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.ntp_server_1", "host", "time2.google.com"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
