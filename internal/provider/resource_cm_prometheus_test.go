package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMPrometheus(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  enabled = true
}
`,
				// Step 2: Check if the resource's 'enabled' attribute is set correctly after apply
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.cm_prometheus", "enabled", "true"),
				),
			},
		},
	})
	// create a new resource with prometheus disable
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  enabled = false
}
`,
				// Step 2: Check if the resource's 'enabled' attribute is set correctly after apply
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.cm_prometheus", "enabled", "false"),
				),
			},
		},
	})
}
