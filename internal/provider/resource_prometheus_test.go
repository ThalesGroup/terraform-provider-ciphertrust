package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Test_CM_AccCipherTrust_Prometheus_ImmutableFields verifies ciphertrust_cm_prometheus is
// created with enabled=true, and that changing enabled (the only user-configurable field)
// is accepted since it is mutable and no ImmutableX() modifiers apply to this resource.
func Test_CM_AccCipherTrust_Prometheus_ImmutableFields(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the resource with enabled=true.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_prometheus.test", "token"),
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "true"),
				),
			},
			// Step 2: Change enabled — this is the only mutable field; no immutability error.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = false
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
