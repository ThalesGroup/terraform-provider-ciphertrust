package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// bootstrapProviderConfig returns the HCL provider block for bootstrap mode.
// Bootstrap mode is only valid on CipherTrust Manager (not CDSPaaS) and only
// before the appliance has been fully configured.
// Password is intentionally omitted from the HCL config; the provider reads it
// from the CIPHERTRUST_PASSWORD environment variable to keep credentials out of
// plaintext test logs.
func bootstrapProviderConfig() string {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	if address == "" {
		address = "https://192.168.2.135"
	}
	username := os.Getenv("CIPHERTRUST_USERNAME")
	if username == "" {
		username = "admin"
	}
	cfg := fmt.Sprintf(`
provider "ciphertrust" {
  address   = %q
  username  = %q
  bootstrap = "yes"
`, address, username)
	if caCert := os.Getenv("CIPHERTRUST_CA_CERT"); caCert != "" {
		cfg += fmt.Sprintf("  ca_cert = %q\n", caCert)
	} else {
		cfg += "  no_ssl_verify = true\n"
	}
	cfg += "}\n"
	return cfg
}

// TestAccCipherTrust_CMSSHKey_ImmutableKey verifies that changing the key on a
// ciphertrust_cm_ssh_key resource produces a plan-time error from ImmutableString.
func TestAccCipherTrust_CMSSHKey_ImmutableKey(t *testing.T) {
	RequireCM(t)
	sshKey := os.Getenv("TEST_SSH_PUBLIC_KEY")
	if sshKey == "" {
		t.Skip("skipping TestAccCipherTrust_CMSSHKey_ImmutableKey: TEST_SSH_PUBLIC_KEY not set")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: bootstrapProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_ssh_key" "test" {
  key = %q
}
`, sshKey),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_ssh_key.test", "id"),
				),
			},
			// Changing key must produce an immutable error at plan time.
			{
				Config: bootstrapProviderConfig() + `
resource "ciphertrust_cm_ssh_key" "test" {
  key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7differentkey test-key-2"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

func TestCipherTrust_CMSSHKey_noopRead(t *testing.T) {
	RequireCM(t)
	sshKey := os.Getenv("TEST_SSH_PUBLIC_KEY")
	if sshKey == "" {
		t.Skip("skipping TestCipherTrust_CMSSHKey_noopRead: TEST_SSH_PUBLIC_KEY not set")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: bootstrapProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_ssh_key" "test" {
  key = %q
}
`, sshKey),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_ssh_key.test", "id"),
				),
			},
			// Verify repeated refresh produces no diff and no error — confirms no-op Read() stability.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
