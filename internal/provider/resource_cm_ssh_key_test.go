package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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

// Test_CM_AccCipherTrust_CMSSHKey_ImmutableKey verifies that changing the key on a
// ciphertrust_cm_ssh_key resource produces a plan-time error from ImmutableString.
func Test_CM_AccCipherTrust_CMSSHKey_ImmutableKey(t *testing.T) {
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

func Test_CM_CipherTrust_CMSSHKey_noopRead(t *testing.T) {
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
			// Verify repeated refresh produces no diff and no error.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCipherTrust_CMSSHKey_OOBDelete verifies that Read() detects an out-of-band
// deletion of the SSH key and removes it from state so a subsequent plan proposes
// recreation. Skipped when TEST_SSH_PUBLIC_KEY is not set, or when the CM API
// does not support SSH key deletion via normal authentication.
func TestCipherTrust_CMSSHKey_OOBDelete(t *testing.T) {
	RequireCM(t)
	sshKey := os.Getenv("TEST_SSH_PUBLIC_KEY")
	if sshKey == "" {
		t.Skip("skipping TestCipherTrust_CMSSHKey_OOBDelete: TEST_SSH_PUBLIC_KEY not set")
	}

	client, ok := createCMClient()
	if !ok {
		t.Skip("skipping TestCipherTrust_CMSSHKey_OOBDelete: createCMClient failed")
	}

	var capturedID string

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
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_ssh_key.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					// Attempt an out-of-band delete via normal authentication.
					// Skip this step if the CM API does not support SSH key deletion.
					_, err := client.DeleteByURL(context.Background(), uuid.New().String(), common.URL_SSH_KEY+"/"+capturedID)
					if err != nil {
						t.Skipf("skipping OOB delete step: CM API returned error on SSH key delete: %s", err.Error())
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestCipherTrust_CMSSHKey_AttributeDrift verifies that Read() produces no false drift
// when the SSH key still exists on CM. The ciphertrust_cm_ssh_key schema exposes only
// the server-assigned id (Computed) and the write-only key material; there are no
// server-settable mutable attributes that can produce attribute-level drift, so this
// test confirms Read() stability: refresh after apply must show no changes.
func TestCipherTrust_CMSSHKey_AttributeDrift(t *testing.T) {
	RequireCM(t)
	sshKey := os.Getenv("TEST_SSH_PUBLIC_KEY")
	if sshKey == "" {
		t.Skip("skipping TestCipherTrust_CMSSHKey_AttributeDrift: TEST_SSH_PUBLIC_KEY not set")
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
			// Verify Read() via GetByIdBootstrap introduces no false attribute drift.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
