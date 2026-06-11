package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const proxyResource = "ciphertrust_proxy.test"

func proxyConfig(noProxyHost string) string {
	return providerConfig + `
resource "ciphertrust_proxy" "test" {
  no_proxy = ["` + noProxyHost + `"]
}
`
}

// TestAccCMProxy_BasicNoDrift verifies that a proxy resource can be created and that
// a subsequent plan shows no drift (Read() correctly round-trips state).
func TestAccCMProxy_BasicNoDrift(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Set proxy no_proxy list; verify the value is in state.
			{
				Config: proxyConfig("192.0.2.1"),
				Check: checkStep(t, "set proxy no_proxy",
					resource.TestCheckResourceAttr(proxyResource, "no_proxy.0", "192.0.2.1"),
				),
			},
			// Step 2: No-drift check — same config, plan must be empty.
			{
				Config:             proxyConfig("192.0.2.1"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
