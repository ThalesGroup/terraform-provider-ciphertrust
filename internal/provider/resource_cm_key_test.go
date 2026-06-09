package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMKey(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_users_list" "users_list" {
  filters = {
    username = "admin"
  }
}

resource "ciphertrust_cm_key" "cte_key" {
  name="terraform"
  algorithm="aes"
  key_size=256
  usage_mask=76
  undeletable=false
  unexportable=false
  meta={
    owner_id=tolist(data.ciphertrust_cm_users_list.users_list.users)[0].user_id
    permissions={
      decrypt_with_key=["CTE Clients"]
      encrypt_with_key=["CTE Clients"]
      export_key=["CTE Clients"]
      mac_verify_with_key=["CTE Clients"]
      mac_with_key=["CTE Clients"]
      read_key=["CTE Clients"]
      sign_verify_with_key=["CTE Clients"]
      sign_with_key=["CTE Clients"]
      use_key=["CTE Clients"]
    }
    cte={
      persistent_on_client=true
      encryption_mode="CBC"
      cte_versioned=false
    }
    xts=false
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.cte_key", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "cte_key" {
  name="terraform_upd"
  algorithm="aes"
  key_size=256
  usage_mask=13
  description="updated via terraform"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.cte_key", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func cmKeyHMACConfig(algorithm string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name      = "tf-test-hmac-%s"
  algorithm = %q
}
`, uuid.NewString()[:8], algorithm)
}

// TestAccCMKey_HMACAlgorithmNoDriftAndUppercaseState verifies that a key created
// with a lowercase HMAC algorithm stores the uppercase form in state, and that a
// subsequent plan produces no changes.
func TestAccCMKey_HMACAlgorithmNoDriftAndUppercaseState(t *testing.T) {
	if _, ok := createCMClient(); !ok {
		t.Skip("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
	}

	cfg := cmKeyHMACConfig("hmac-sha256")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with lowercase algorithm; state must store uppercase.
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "algorithm", "HMAC-SHA256"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
				),
			},
			{
				// Step 2: re-apply same config; plan must be empty (no drift).
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccCMKey_HMACAlgorithmRemainingVariants covers hmac-sha1, hmac-sha384, and
// hmac-sha512 (hmac-sha256 is covered by TestAccCMKey_HMACAlgorithmNoDriftAndUppercaseState).
func TestAccCMKey_HMACAlgorithmRemainingVariants(t *testing.T) {
	if _, ok := createCMClient(); !ok {
		t.Skip("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
	}

	variants := []struct {
		lower string
		upper string
	}{
		{"hmac-sha1", "HMAC-SHA1"},
		{"hmac-sha384", "HMAC-SHA384"},
		{"hmac-sha512", "HMAC-SHA512"},
	}

	for _, v := range variants {
		v := v
		t.Run(v.lower, func(t *testing.T) {
			cfg := cmKeyHMACConfig(v.lower)
			resource.Test(t, resource.TestCase{
				ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
				Steps: []resource.TestStep{
					{
						Config: cfg,
						Check: resource.ComposeAggregateTestCheckFunc(
							resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "algorithm", v.upper),
							resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
						),
					},
					{
						Config:   cfg,
						PlanOnly: true,
					},
				},
			})
		})
	}
}

// TestAccCMKey_ReadDrift_OutOfBandDelete verifies that deleting a key out-of-band
// causes Read() to call RemoveResource (404 path), and a subsequent plan proposes recreation.
func TestAccCMKey_ReadDrift_OutOfBandDelete(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
	}

	cfg := cmKeyHMACConfig("hmac-sha256")
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key and capture its ID.
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_cm_key.test"]
						if !ok {
							return fmt.Errorf("resource ciphertrust_cm_key.test not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: delete the key out-of-band, then refresh state.
				// Read() should detect 404 and remove the resource from state,
				// causing the plan to show a create diff.
				PreConfig: func() {
					if capturedID == "" {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"oob-delete-test",
						common.URL_KEY_MANAGEMENT+"/"+capturedID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMKey_AlgorithmValidatorAcceptsUppercase verifies that an uppercase HMAC
// algorithm (as stored in state after round-trip) passes the validator and causes
// no plan diff on a second apply.
func TestAccCMKey_AlgorithmValidatorAcceptsUppercase(t *testing.T) {
	if _, ok := createCMClient(); !ok {
		t.Skip("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
	}

	cfg := cmKeyHMACConfig("HMAC-SHA256")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with uppercase algorithm; must apply without validation error.
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "algorithm", "HMAC-SHA256"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
				),
			},
			{
				// Step 2: no drift on second plan.
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}
