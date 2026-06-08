package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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
			// Update and Read testing. Note: key name is not PATCH-able on CipherTrust
			// Manager, so the name is kept identical to the create step; only patchable
			// attributes (usage_mask, description) are changed. With the real Read() now
			// in place, renaming here would surface unreconcilable drift.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_key" "cte_key" {
  name="terraform"
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

// testAccCMKeyConfig returns a minimal ciphertrust_cm_key configuration whose
// attributes are all refreshed by Read, so a clean apply produces an empty follow-up
// plan and any drift introduced out-of-band is detectable.
func testAccCMKeyConfig(name, description string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "drift" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  usage_mask  = 76
  undeletable = false
  unexportable = false
  description = %q
  labels = {
    env = "acc-test"
  }
}
`, name, description)
}

// testAccCMKeyCaptureID stores the id of the named resource into dst so that a
// later TestStep.PreConfig can act on the key directly via the CM API.
func testAccCMKeyCaptureID(resourceName string, dst *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found in state: %s", resourceName)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("resource %s has no id set", resourceName)
		}
		*dst = rs.Primary.ID
		return nil
	}
}

// TestAccCipherTrustCMKey_basic applies a minimal key and relies on the test
// framework's implicit post-apply refresh-and-plan to prove that Read repopulates
// every tracked attribute without introducing spurious drift (empty plan).
func TestAccCipherTrustCMKey_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMKeyConfig("tf-acc-cmkey-basic", "basic"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.drift", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift", "name", "tf-acc-cmkey-basic"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift", "description", "basic"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift", "labels.env", "acc-test"),
				),
			},
		},
	})
}

// TestAccCipherTrustCMKey_import verifies that an existing key can be brought under
// Terraform management by its id. ImportStateVerify is intentionally not enabled:
// nearly every cm_key attribute is Optional (not Computed), and the guarded Read only
// refreshes attributes already tracked in state, so a freshly-imported resource carries
// just its id until the user supplies the matching configuration. The check confirms the
// import seeds the resource id (exercising ImportState -> Read).
func TestAccCipherTrustCMKey_import(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMKeyConfig("tf-acc-cmkey-import", "import"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.drift", "id"),
				),
			},
			{
				ResourceName:      "ciphertrust_cm_key.drift",
				ImportState:       true,
				ImportStateVerify: false,
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected 1 imported instance, got %d", len(states))
					}
					if states[0].ID == "" {
						return fmt.Errorf("imported instance has no id")
					}
					return nil
				},
			},
		},
	})
}

// TestAccCipherTrustCMKey_driftDetection_outOfBandDelete deletes the key directly on
// CipherTrust Manager between steps and asserts that the subsequent refresh removes
// the resource from state (the 404 -> RemoveResource path), so the plan is non-empty
// (a recreate).
func TestAccCipherTrustCMKey_driftDetection_outOfBandDelete(t *testing.T) {
	var keyID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMKeyConfig("tf-acc-cmkey-oob-delete", "oob-delete"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCMKeyCaptureID("ciphertrust_cm_key.drift", &keyID),
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(context.Background(), "tf-acc-oob-delete-cmkey", common.URL_KEY_MANAGEMENT+"/"+keyID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMKey_driftDetection_outOfBandModify patches a tracked attribute
// on CipherTrust Manager between steps and asserts that the subsequent refresh
// surfaces the drift as a non-empty plan (the Read-refresh path).
func TestAccCipherTrustCMKey_driftDetection_outOfBandModify(t *testing.T) {
	var keyID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMKeyConfig("tf-acc-cmkey-oob-modify", "before-drift"),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCMKeyCaptureID("ciphertrust_cm_key.drift", &keyID),
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := []byte(`{"description":"after-drift","labels":{"env":"modified"}}`)
					_, _ = client.UpdateData(context.Background(), keyID, common.URL_KEY_MANAGEMENT, payload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMKey_updateInPlace changes tracked attributes via config and
// re-applies, then asserts Read reflects the new values in state.
func TestAccCipherTrustCMKey_updateInPlace(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMKeyConfig("tf-acc-cmkey-update", "initial"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift", "description", "initial"),
				),
			},
			{
				Config: testAccCMKeyConfig("tf-acc-cmkey-update", "updated-in-place"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift", "description", "updated-in-place"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift", "labels.env", "acc-test"),
				),
			},
		},
	})
}

// TestAccCipherTrustCMKey_readPreservesWriteOnlyAttrs imports key material (a
// write-only, sensitive input that the CM key object never returns) and asserts that
// a refresh does not clobber it with an empty value from the API response.
func TestAccCipherTrustCMKey_readPreservesWriteOnlyAttrs(t *testing.T) {
	const keyMaterial = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "imported" {
  name      = "tf-acc-cmkey-writeonly"
  algorithm = "aes"
  key_size  = 256
  encoding  = "hex"
  material  = %q
}
`, keyMaterial)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.imported", "material", keyMaterial),
				),
			},
			{
				// Refresh-only: Read runs against CM (which never returns material) and
				// must leave the prior write-only value untouched.
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.imported", "material", keyMaterial),
				),
			},
		},
	})
}
