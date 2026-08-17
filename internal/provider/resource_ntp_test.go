package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Test_CM_NTP_KeyReplacement verifies that key is write-only (never stored in state) and
// that bumping key_version — not changing key alone — is what triggers replacement
// (destroy-then-create) with the new key. Terraform Core excludes a write-only
// attribute's own value from diff computation, so key_version is the only signal
// available to force the resource to pick up a rotated key.
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
  host        = %q
  key         = %q
  key_version = 1
  key_type    = "SHA-1"
}
`, uniqueHost, key1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", uniqueHost),
					resource.TestCheckNoResourceAttr("ciphertrust_ntp.test", "key"),
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "key_version", "1"),
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "key_type", "SHA-1"),
				),
			},
			// Step 2: Same key_version, changed key value — no diff, key is not resent.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_ntp" "test" {
  host        = %q
  key         = %q
  key_version = 1
  key_type    = "SHA-1"
}
`, uniqueHost, key2),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 3: Bump key_version — triggers declarative replacement (destroy-then-create) with key2.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_ntp" "test" {
  host        = %q
  key         = %q
  key_version = 2
  key_type    = "SHA-1"
}
`, uniqueHost, key2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", uniqueHost),
					resource.TestCheckNoResourceAttr("ciphertrust_ntp.test", "key"),
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "key_version", "2"),
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
