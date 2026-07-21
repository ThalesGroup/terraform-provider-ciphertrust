package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_CM_NTP_KeyReplacement(t *testing.T) {
	RequireCM(t)
	uniqueHost := "ntp-test-" + uuid.New().String()[:8] + ".example.com"
	key1 := "key-content-1-here-very-long-string-value-must-be-valid-for-ntp"
	key2 := "key-content-2-here-very-long-string-value-must-be-valid-for-ntp"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create NTP resource with key1
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_ntp" "test" {
  host     = %q
  key      = %q
  key_type = "SHA-1"
}
`, uniqueHost, key1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", uniqueHost),
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "key", key1),
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "key_type", "SHA-1"),
				),
			},
			// Step 2: Update NTP key — should trigger declarative replacement (destroy-then-create)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_ntp" "test" {
  host     = %q
  key      = %q
  key_type = "SHA-1"
}
`, uniqueHost, key2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", uniqueHost),
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "key", key2),
				),
			},
		},
	})
}

func Test_CM_NTP_NoKeyAppliesCleanly(t *testing.T) {
	RequireCM(t)
	uniqueHost := "ntp-test-nokey-" + uuid.New().String()[:8] + ".example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create NTP server without key
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_ntp" "test" {
  host = %q
}
`, uniqueHost),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", uniqueHost),
					resource.TestCheckNoResourceAttr("ciphertrust_ntp.test", "key"),
					resource.TestCheckNoResourceAttr("ciphertrust_ntp.test", "key_id"),
					resource.TestCheckNoResourceAttr("ciphertrust_ntp.test", "key_type"),
				),
			},
		},
	})
}
