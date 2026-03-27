package provider

import (
	"regexp"
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
					resource.TestCheckResourceAttrSet("ciphertrust_ntp.ntp_server_1", "host"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "ntp_server_1" {
  host = "time2.google.com"
}
`,
				ExpectError: regexp.MustCompile(`Updating NTP configuration is not supported`),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
