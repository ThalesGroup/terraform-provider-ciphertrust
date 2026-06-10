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

// TestAccCMKey_driftDetection verifies that an out-of-band attribute change is
// detected by Terraform on the next plan, confirming Read() re-fetches live state.
func TestAccCMKey_driftDetection(t *testing.T) {
	keyName := "tf-drift-" + uuid.New().String()[:8]
	resourceAddr := "ciphertrust_cm_key.test"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  description = "original"
}
`, keyName)

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key and capture its ID for later OOB mutation.
				Config: config,
				Check: checkStep(t, "create key",
					resource.TestCheckResourceAttrSet(resourceAddr, "id"),
					resource.TestCheckResourceAttr(resourceAddr, "description", "original"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceAddr]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceAddr)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: verify no spurious drift immediately after create.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: mutate description out-of-band, then plan — drift must be detected.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := []byte(`{"description":"modified"}`)
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, payload, "id")
				},
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMKey_readPopulatesState verifies that Read() populates all Saved=Yes scalar
// fields into Terraform state so they reflect live API values after a refresh.
func TestAccCMKey_readPopulatesState(t *testing.T) {
	keyName := "tf-read-" + uuid.New().String()[:8]
	resourceAddr := "ciphertrust_cm_key.test"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name         = %q
  algorithm    = "aes"
  key_size     = 256
  usage_mask   = 76
  unexportable = false
  undeletable  = false
  description  = "readtest"
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key; verify essential attributes are set.
				Config: config,
				Check: checkStep(t, "create key",
					resource.TestCheckResourceAttrSet(resourceAddr, "id"),
					resource.TestCheckResourceAttr(resourceAddr, "algorithm", "aes"),
					resource.TestCheckResourceAttr(resourceAddr, "key_size", "256"),
					resource.TestCheckResourceAttr(resourceAddr, "usage_mask", "76"),
				),
			},
			{
				// Step 2: no-drift check — plan must be empty immediately after create.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: explicit refresh — Read() re-fetches from API and populates state.
				RefreshState: true,
				Check: checkStep(t, "state populated after refresh",
					resource.TestCheckResourceAttr(resourceAddr, "algorithm", "aes"),
					resource.TestCheckResourceAttr(resourceAddr, "key_size", "256"),
					resource.TestCheckResourceAttr(resourceAddr, "usage_mask", "76"),
					resource.TestCheckResourceAttr(resourceAddr, "unexportable", "false"),
					resource.TestCheckResourceAttr(resourceAddr, "undeletable", "false"),
					resource.TestCheckResourceAttr(resourceAddr, "name", keyName),
					resource.TestCheckResourceAttr(resourceAddr, "description", "readtest"),
					resource.TestCheckResourceAttrSet(resourceAddr, "state"),
				),
			},
		},
	})
}

// TestAccCMKey_oobDeleteRemovesFromState verifies that when a key is deleted
// out-of-band, Read() calls RemoveResource so Terraform plans to re-create it.
func TestAccCMKey_oobDeleteRemovesFromState(t *testing.T) {
	keyName := "tf-oobdel-" + uuid.New().String()[:8]
	resourceAddr := "ciphertrust_cm_key.test"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
}
`, keyName)

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key and capture its ID for out-of-band deletion.
				Config: config,
				Check: checkStep(t, "create key",
					resource.TestCheckResourceAttrSet(resourceAddr, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceAddr]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceAddr)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: no-drift check.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: delete key out-of-band; refresh detects 404 → RemoveResource.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					traceID := uuid.New().String()
					_, _ = client.DeleteByID(context.Background(), "DELETE", traceID, common.URL_KEY_MANAGEMENT+"/"+capturedID, []byte{})
				},
				RefreshState: true,
				Check: checkStep(t, "resource removed from state after OOB delete",
					func(s *terraform.State) error {
						// testAccListResourceAttributes asserts zero attributes: when RemoveResource
						// was called the resource is absent from state, so the helper returns an
						// error ("did not find resource…") — that absence is the expected outcome.
						if err := testAccListResourceAttributes(resourceAddr)(s); err == nil {
							return fmt.Errorf("expected resource %s to have zero attributes (absent from state) after OOB delete", resourceAddr)
						}
						return nil
					},
				),
			},
			{
				// Step 4: plan must be non-empty because resource was removed from state
				// and needs to be re-created.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMKey_writeOnlyFieldsPreserved verifies that write-only fields (e.g. material)
// are preserved verbatim through Read() and not cleared by the Saved=No path.
func TestAccCMKey_writeOnlyFieldsPreserved(t *testing.T) {
	keyName := "tf-wo-" + uuid.New().String()[:8]
	resourceAddr := "ciphertrust_cm_key.test"
	const testMaterial = "00112233445566778899aabbccddeeff"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name      = %q
  algorithm = "aes"
  key_size  = 128
  material  = %q
}
`, keyName, testMaterial)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key with imported material; verify material is in state.
				Config: config,
				Check: checkStep(t, "create key with material",
					resource.TestCheckResourceAttrSet(resourceAddr, "id"),
					resource.TestCheckResourceAttr(resourceAddr, "material", testMaterial),
				),
			},
			{
				// Step 2: no-drift check — material preserved in state matches config.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: refresh — Read() must preserve material (Saved=No field).
				RefreshState: true,
				Check: checkStep(t, "material preserved after refresh",
					resource.TestCheckResourceAttr(resourceAddr, "material", testMaterial),
				),
			},
		},
	})
}
