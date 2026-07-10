package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Test_CM_Proxy_CreateUpdate verifies that a ciphertrust_proxy singleton resource can be
// configured with an http_proxy URL (Step 1) and then updated to a different URL (Step 2).
// The proxy resource has no id attribute — it is a singleton that configures outbound
// proxy settings on the CipherTrust Manager appliance.
// Required env vars: CM_TEST_HTTP_PROXY (initial URL), CM_TEST_HTTP_PROXY_UPDATED (updated URL).
func Test_CM_Proxy_CreateUpdate(t *testing.T) {
	RequireCM(t)

	httpProxy := os.Getenv("CM_TEST_HTTP_PROXY")
	if httpProxy == "" {
		t.Skip("CM_TEST_HTTP_PROXY not set — skipping proxy acceptance test")
	}
	httpProxyUpdated := os.Getenv("CM_TEST_HTTP_PROXY_UPDATED")
	if httpProxyUpdated == "" {
		t.Skip("CM_TEST_HTTP_PROXY_UPDATED not set — skipping proxy acceptance test")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccProxyConfig(httpProxy),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "http_proxy"),
				),
			},
			{
				Config: testAccProxyConfig(httpProxyUpdated),
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttrSet("ciphertrust_proxy.test", "http_proxy"),
				),
			},
		},
	})
}

func testAccProxyConfig(httpProxy string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_proxy" "test" {
  http_proxy = %q
}
`, httpProxy)
}
