package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_CM_ResourceSyslog(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Include port and message_format explicitly to match CM defaults and
				// prevent drift on the post-apply refresh plan check.
				Config: providerConfig + `
resource "ciphertrust_syslog" "syslog_1" {
    host           = "example.syslog.com"
    transport      = "udp"
    port           = 514
    message_format = "rfc5424"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_syslog.syslog_1", "host", "example.syslog.com"),
					resource.TestCheckResourceAttr("ciphertrust_syslog.syslog_1", "port", "514"),
				),
			},
			{
				// host is immutable — changing it must produce a plan-time error.
				Config: providerConfig + `
resource "ciphertrust_syslog" "syslog_1" {
    host           = "example1.syslog.com"
    transport      = "udp"
    port           = 514
    message_format = "rfc5424"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
