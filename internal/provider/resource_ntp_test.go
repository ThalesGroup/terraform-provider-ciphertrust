package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

func TestAccCMNTP_KeyTypeComputedAndStable(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host = "time1.google.com"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_ntp.test", "key_type"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host = "time1.google.com"
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCMNTP_KeyTypeRequiresReplace(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host     = "time1.google.com"
  key      = "1"
  key_type = "SHA-256"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "key_type", "SHA-256"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host     = "time1.google.com"
  key      = "1"
  key_type = "SHA-512"
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("ciphertrust_ntp.test", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "key_type", "SHA-512"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host     = "time1.google.com"
  key      = "1"
  key_type = "SHA-512"
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

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
