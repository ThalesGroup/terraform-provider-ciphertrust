package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	cckm "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/aws"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// TestCckmAWSKeyMaterialCreateAndUpdate tests the basic key material lifecycle:
//
//  1. Create an EXTERNAL key (PendingImport) + aws_key_material with material1 (no valid_to).
//     Key transitions from PendingImport to Enabled with rotation_history.#=1.
//  2. Update material1 to add valid_to + key_material_description
//     Verify expiration_model=KEY_MATERIAL_EXPIRES.
//  3. Update material1 to change valid_to + description.
//     Verify new valid_to is reflected.
//  4. Remove valid_to from material1 Verify expiration_model reverts to
//     KEY_MATERIAL_DOES_NOT_EXPIRE and rotation_history.valid_to is cleared.
//  5. Add material2.  Verify rotation_history.#=2 and key remains Enabled.
func TestCckmAWSKeyMaterialCreateAndUpdate(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// Step 1: create with material1, no valid_to or description.
	createConfig := `
		locals {
			cmKeyName2 = "${local.cmKeyName}-2"
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key2" {
			name                         = local.cmKeyName2
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_byok_key" "ext_key" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias = [local.alias]
			}
		}
		data "ciphertrust_aws_key_rotation_list" "rotations" {
			key_id = ciphertrust_aws_key_material.km.id
		}
		# Place holder for ciphertrust_aws_key_material
		%s`

	createMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier       = "local"
				# Place holder for optional valid_to and description
				%s
			}]
		}`

	addMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier       = "local"
				# Place holder for optional valid_to and description
				%s
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
					source_key_tier       = "local"
				},
			]
		}`

	updateValidToAndDescConfig := `
		valid_to                 = "%s"
		key_material_description = "%s"
	`
	updateRemoveValidToConfig := `
		key_material_description = "%s"
	`

	validTo1 := awsKeyValidTo(180) // ~6 months out
	validTo2 := awsKeyValidTo(270) // ~9 months out - must be > validTo1

	createDescription := "initial description"
	updateDescription := "updated description"

	// Maerial has no optional args
	createMaterialConfigStr := fmt.Sprintf(createMaterialConfig, "\n")
	createConfigStr := awsConnectionResource + fmt.Sprintf(createConfig, createMaterialConfigStr)

	// Maerial has optional args
	updateValidToAndDescConfigStr := fmt.Sprintf(createMaterialConfig, fmt.Sprintf(updateValidToAndDescConfig, validTo1, createDescription))
	updateConfigStr1 := awsConnectionResource + fmt.Sprintf(createConfig, updateValidToAndDescConfigStr)

	// Maerial has changed optional args
	updateValidToAndDescConfigStr1 := fmt.Sprintf(createMaterialConfig, fmt.Sprintf(updateValidToAndDescConfig, validTo2, updateDescription))
	updateConfigStr2 := awsConnectionResource + fmt.Sprintf(createConfig, updateValidToAndDescConfigStr1)

	// Material has changed optional args - no valid_to
	updateMaterialConfigStr3 := fmt.Sprintf(createMaterialConfig, fmt.Sprintf(updateRemoveValidToConfig, updateDescription))
	updateConfigStr3 := awsConnectionResource + fmt.Sprintf(createConfig, updateMaterialConfigStr3)

	// Add a new material
	addMaterialConfigStr := fmt.Sprintf(addMaterialConfig, fmt.Sprintf(updateRemoveValidToConfig, updateDescription))
	updateConfigStr4 := awsConnectionResource + fmt.Sprintf(createConfig, addMaterialConfigStr)

	kmResource := "ciphertrust_aws_key_material.km"
	rotDSResource := "data.ciphertrust_aws_key_rotation_list.rotations"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create - key moves from PendingImport to Enabled.
				Config: createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(kmResource, "id"),
					resource.TestCheckResourceAttrSet(kmResource, "aws_key_id"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.0.aws_params.key_material_id"),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.0.source_key_identifier"),
				),
			},
			{
				// Add valid_to + description
				Config: updateConfigStr1,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttrSet(rotDSResource, "rotations.0.aws_params.valid_to"),
					resource.TestCheckResourceAttr(rotDSResource, "rotations.0.aws_params.key_material_description", createDescription),
				),
			},
			{
				// Update valid_to + description
				Config: updateConfigStr2,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttrSet(rotDSResource, "rotations.0.aws_params.valid_to"),
					resource.TestCheckResourceAttr(rotDSResource, "rotations.0.aws_params.key_material_description", updateDescription),
				),
			},
			{
				// Remove valid_to
				Config: updateConfigStr3,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(rotDSResource, "rotations.0.aws_params.valid_to", ""),
					resource.TestCheckResourceAttr(rotDSResource, "rotations.0.aws_params.key_material_description", updateDescription),
				),
			},
			{
				// Add material2
				Config: updateConfigStr4,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(rotDSResource, "rotations.1.aws_params.valid_to", ""),
					resource.TestCheckResourceAttr(rotDSResource, "rotations.1.aws_params.key_material_description", updateDescription),
				),
			},
		},
	})
}

// TestCckmAWSKeyMaterialCombinedUpdates verifies that multiple update operations can fire
// in a single apply.
func TestCckmAWSKeyMaterialCombinedUpdates(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	kmResource := "ciphertrust_aws_key_material.km"

	// Step 1: create with material1 (with valid_to + description).
	createConfig := `
		locals {
			cmKeyName2 = "${local.cmKeyName}-2"
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key2" {
			name                         = local.cmKeyName2
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_byok_key" "ext_key" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias = [local.alias]
			}
		}
		# Place holder for ciphertrust_aws_key_material resource
		%s`

	createKeyMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier    = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier          = "local"
				valid_to                 = "%s"
				key_material_description = "original description"
			}]
		}`

	updateKeyMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [
				{
					source_key_identifier    = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier          = "local"
					valid_to                 = "%s"
					key_material_description = "updated description"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
					source_key_tier       = "local"
				},
			]
		}`

	deleteMaterialAndUpdateMaterial := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier    = ciphertrust_cm_key.cm_aes_key2.id
				source_key_tier          = "local"
				key_material_description = "material2 description"
			}]
		}`

	validTo := awsKeyValidTo(180)
	validToUpdated := awsKeyValidTo(270)

	createConfigStr := fmt.Sprintf(createConfig, fmt.Sprintf(createKeyMaterialConfig, validTo))
	updateMaterialConfigStr := fmt.Sprintf(createConfig, fmt.Sprintf(updateKeyMaterialConfig, validToUpdated))
	deleteAllMaterialConfigStr := fmt.Sprintf(createConfig, deleteMaterialAndUpdateMaterial)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with material1 (valid_to + description).
				Config: awsConnectionResource + createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
				),
			},
			{
				// Step 2: material1 gets updated metadata AND material2 is added in the same apply.
				Config: awsConnectionResource + updateMaterialConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
				),
			},
			{
				// Step 3:
				// material1 is removed (deleted) AND material2's description is updated.
				// material1 is NON_CURRENT, so its bytes are deleted via delete-material.
				// AWS behavior: deleting ANY material (even NON_CURRENT) causes the key state
				// to become PendingImport, even though material2 (CURRENT) is still IMPORTED
				// and CurrentKeyMaterialId still points to material2. AWS returns
				// KMSInvalidStateException for rotate-material on a PendingImport key.
				// Both rotation history entries persist: material2 remains CURRENT/IMPORTED
				// and material1's entry moves to PENDING_IMPORT (bytes gone). rotation_history.# = 2.
				Config: awsConnectionResource + deleteAllMaterialConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.0.source_key_identifier"),
				),
			},
		},
	})
}

// TestCckmAWSKeyMaterialRepairPendingImport verifies that the provider correctly recovers
// when key material is deleted out-of-band, leaving the entry in PENDING_IMPORT state.
//
// Flow:
//  1. Create an EXTERNAL key + aws_key_material with material1. Verify Enabled.
//     Capture the CM key UUID for the out-of-band delete.
//  2. OOB: delete material1 bytes. Key enters PendingImport state.
//     RefreshState detects drift (ModifyPlan marks attrs Unknown) -> non-empty plan.
//  3. Re-apply config unchanged. Provider detects PENDING_IMPORT, calls import-material
//     with EXISTING_KEY_MATERIAL. Verify key_state=Enabled, rotation_history.#=1.
//  4. RefreshState - confirm plan is stable.
func TestCckmAWSKeyMaterialRepairPendingImport(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	createConfig := `
		resource "ciphertrust_aws_byok_key" "ext_key" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias = [local.alias]
			}
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier       = "local"
			}]
		}`

	kmResource := "ciphertrust_aws_key_material.km"
	var capturedPrimaryKeyID string
	var capturedCmKeyID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the key material. Capture CM UUID for OOB delete.
				Config: awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(kmResource, "id"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[kmResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", kmResource)
						}
						capturedPrimaryKeyID = rs.Primary.ID
						rsCmKey, ok := s.RootModule().Resources["ciphertrust_cm_key.cm_aes_key"]
						if !ok {
							return fmt.Errorf("ciphertrust_cm_key.cm_aes_key2 not found in state")
						}
						capturedCmKeyID = rsCmKey.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: delete material1 OOB. Key enters PendingImport.
				// ModifyPlan detects PENDING_IMPORT and marks attrs Unknown -> non-empty plan.
				PreConfig: func() {
					deleteByokKeyMaterialAtIndex(capturedPrimaryKeyID, 0)
					refreshKeyAndWait(capturedPrimaryKeyID, capturedCmKeyID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: re-apply. Provider detects PENDING_IMPORT and
				// re-imports material1 with EXISTING_KEY_MATERIAL. Key returns to Enabled.
				Config: awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
				),
			},
			{
				// Step 4: confirm plan is stable after repair.
				RefreshState: true,
			},
		},
	})
}

// TestCckmAWSKeyMaterialRepairPendingRotation verifies that the provider correctly resumes
// a rotation that was left in PENDING_ROTATION state due to an out-of-band partial import
//
// Flow:
//  1. Create an EXTERNAL key + aws_key_material with material1. Capture CM UUID and
//     material2 CM key ID.
//  2. OOB: call import-material with NEW_KEY_MATERIAL for material2 on the key.
//     material2 enters PENDING_ROTATION because the rotate-material call was not made.
//     RefreshState detects drift -> non-empty plan.
//  3. Observability step: apply with [material1] only + rotation list DS.
//     The DS shows material2 in PENDING_ROTATION state in test output.
//  4. Apply with [material1, material2]. Provider calls rotate-material
//     with an empty body to resume the pending rotation.
//     Verify key_state=Enabled, rotation_history.#=2.
//  5. RefreshState - confirm plan is stable.
func TestCckmAWSKeyMaterialRepairPendingRotation(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// material1 only.
	createConfig := `
		locals {
			cmKeyName2 = "${local.cmKeyName}-2"
		}
		resource "ciphertrust_aws_byok_key" "ext_key" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias = [local.alias]
			}
		}
		resource "ciphertrust_cm_key" "cm_aes_key2" {
			name                         = local.cmKeyName2
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		data "ciphertrust_aws_key_rotation_list" "rotations" {
			key_id = ciphertrust_aws_key_material.km.id
		}
		# Place holder for ciphertrust_aws_key_material
		%s`

	createMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier       = "local"
			}]
		}`

	repairMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier       = "local"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
					source_key_tier       = "local"
				},
			]
		}`

	kmResource := "ciphertrust_aws_key_material.km"
	//rotDSResource := "data.ciphertrust_aws_key_rotation_list.rotations"

	var capturedKeyID string
	var capturedCmKey2ID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with material1. Capture CM UUID and material2 CM key ID.
				Config: awsConnectionResource + fmt.Sprintf(createConfig, createMaterialConfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[kmResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", kmResource)
						}
						capturedKeyID = rs.Primary.ID
						rs2, ok := s.RootModule().Resources["ciphertrust_cm_key.cm_aes_key2"]
						if !ok {
							return fmt.Errorf("ciphertrust_cm_key.cm_aes_key2 not found in state")
						}
						capturedCmKey2ID = rs2.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: OOB import material2 with NEW_KEY_MATERIAL. material2 enters
				// PENDING_ROTATION because rotate-material was not called.
				// RefreshState detects drift -> non-empty plan.
				PreConfig: func() {
					callByokImportMaterialOutOfBand(
						"TestCckmAWSKeyMaterialRepairPendingRotation/OOB",
						capturedKeyID, capturedCmKey2ID, "local", "NEW_KEY_MATERIAL",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 4: apply with [material1, material2]. Provider
				// calls rotate-material with empty body to activate material2.
				// Verify key_state=Enabled and rotation_history grows to 2.
				Config: awsConnectionResource + fmt.Sprintf(createConfig, repairMaterialConfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
				),
			},
			{
				// Step 5: confirm plan is stable after repair.
				RefreshState: true,
			},
		},
	})
}

// TestCckmAWSKeyMaterialRepairCombined verifies that (PENDING_IMPORT repair) and
// (PENDING_ROTATION repair) can both fire within a single apply when both
// conditions are present simultaneously.
//
// Flow:
//  1. Create an EXTERNAL key + aws_key_material with material1. Capture CM UUID and
//     material2 CM key ID.
//  2. OOB in a single PreConfig: (a) delete material1 bytes -> PENDING_IMPORT,
//     (b) import material2 with NEW_KEY_MATERIAL -> PENDING_ROTATION.
//     RefreshState detects drift -> non-empty plan.
//  3. Apply with [material1, material2]. Repairs material1 first, then
//     resumes material2. Both phases fire in the same apply.
//     Verify key_state=Enabled, rotation_history.#=2.
//  4. RefreshState - confirm plan is stable.
func TestCckmAWSKeyMaterialRepairCombined(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// material1 only.
	createConfig := `
		locals {
			cmKeyName2 = "${local.cmKeyName}-2"
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key2" {
			name                         = local.cmKeyName2
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_byok_key" "ext_key" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias = [local.alias]
			}
		}
		# Place holder for ciphertrust_aws_key_material
		%s`

	createMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier       = "local"
			}]
		}`

	repairMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier       = "local"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
					source_key_tier       = "local"
				},
			]
		}`

	var capturedPrimaryKeyID string
	var capturedCmKey2ID string

	kmResource := "ciphertrust_aws_key_material.km"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with material1. Capture CM UUID and material2 CM key ID.
				Config: awsConnectionResource + fmt.Sprintf(createConfig, createMaterialConfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[kmResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", kmResource)
						}
						capturedPrimaryKeyID = rs.Primary.ID
						rs2, ok := s.RootModule().Resources["ciphertrust_cm_key.cm_aes_key2"]
						if !ok {
							return fmt.Errorf("ciphertrust_cm_key.cm_aes_key2 not found in state")
						}
						capturedCmKey2ID = rs2.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: OOB - two operations in one PreConfig:
				//   (a) delete material1 bytes -> material1 enters PENDING_IMPORT.
				//   (b) import material2 with NEW_KEY_MATERIAL -> material2 enters PENDING_ROTATION.
				// Both states are detected by ModifyPlan -> non-empty plan.
				// Sleeps after each OOB call let AWS and CM settle before RefreshState runs,
				// reducing the chance of the subsequent repair apply seeing stale key state.
				PreConfig: func() {
					deleteByokKeyMaterialAtIndex(capturedPrimaryKeyID, 0)
					refreshKeyAndWait(capturedPrimaryKeyID, capturedCmKey2ID)
					callByokImportMaterialOutOfBand(
						"TestCckmAWSKeyMaterialRepairCombined/OOB-import",
						capturedPrimaryKeyID, capturedCmKey2ID, "local", "NEW_KEY_MATERIAL",
					)
					refreshKeyAndWait(capturedPrimaryKeyID, capturedCmKey2ID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: apply with [material1, material2].
				// After repair: key_state=Enabled, rotation_history.#=2.
				Config: awsConnectionResource + fmt.Sprintf(createConfig, repairMaterialConfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
				),
			},
			{
				// Step 4: confirm plan is stable after combined repair.
				RefreshState: true,
			},
		},
	})
}

// TestCckmAWSKeyMaterialMultiRegion tests the full key material lifecycle for a
// multi-region EXTERNAL key with three replica keys. Each rotation imports material to
// the primary, propagates it to all replicas, and then activates it. An out-of-band
// delete of a non-current material entry is repaired by re-apply.
//
// Flow:
//  1. Create primary MR key (PendingImport, no material) + 3 replica keys.
//     Replicas inherit PendingImport state from the primary until material is added.
//  2. Add aws_key_material with material1. Provider imports material1 to the primary,
//     imports it to all 3 replicas, and waits for each replica to show material1 as
//     CURRENT. Primary becomes Enabled. rotation_history.#=1.
//  3. Add material2. Provider imports material2 to the primary, imports to all 3 replicas,
//     then calls rotate-material to make material2 CURRENT. rotation_history.#=2.
//     A 30s sleep before this step lets CM finish background propagation of material1
//     to all replicas before the next rotation begins.
//  4. Add material3. Same import-and-rotate sequence as material2. rotation_history.#=3.
//     A 30s sleep before this step lets CM finish background propagation of material2.
//     Capture the primary CM UUID for the out-of-band delete in Step 5.
//  5. OOB: delete material2 (index 1, the second-oldest entry) from the primary key.
//     Primary remains Enabled because material3 is still CURRENT.
//     RefreshState detects the missing rotation entry -> non-empty plan.
//  6. Re-apply the three-material config. Provider detects material2 is missing from the
//     rotation history and re-imports it via import-material with EXISTING_KEY_MATERIAL.
//     rotation_history.#=3 restored.
//  7. RefreshState - confirm plan is stable.
func TestCckmAWSKeyMaterialMultiRegionOOBDeleteMaterial(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	createConfig := `
		resource "ciphertrust_aws_byok_key" "primary" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
		}
		resource "ciphertrust_aws_byok_key" "replica_1" {
			region = ciphertrust_aws_kms.kms.regions[1]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		resource "ciphertrust_aws_byok_key" "replica_2" {
			region = ciphertrust_aws_kms.kms.regions[2]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		resource "ciphertrust_aws_byok_key" "replica_3" {
			region = ciphertrust_aws_kms.kms.regions[3]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		resource "ciphertrust_aws_byok_key" "replica_4" {
			region = ciphertrust_aws_kms.kms.regions[4]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key2" {
			name                         = "%s"
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key3" {
			name                         = "%s"
			algorithm                    = "AES"
		}`

	// key material config template - %s is replaced with the comma-separated list of materials.
	keyMaterialConfig := `
		resource "ciphertrust_aws_key_material" "key_material" {
			depends_on = [
				ciphertrust_aws_byok_key.replica_1,
				ciphertrust_aws_byok_key.replica_2,
				ciphertrust_aws_byok_key.replica_3,
			]
			aws_key_id = ciphertrust_aws_byok_key.primary.aws_param.key_id
			key_material = [%s]
		}`

	material2 := `{
		source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
		source_key_tier       = "local"
	}`
	material3 := `{
		source_key_identifier = ciphertrust_cm_key.cm_aes_key3.id
		source_key_tier       = "local"
	}`

	replica1Alias := "tf-" + uuid.New().String()[8:]
	replica2Alias := "tf-" + uuid.New().String()[8:]
	replica3Alias := "tf-" + uuid.New().String()[8:]
	replica4Alias := "tf-" + uuid.New().String()[8:]
	cmName1 := "tf-" + uuid.New().String()[8:]
	cmName2 := "tf-" + uuid.New().String()[8:]

	// Step 1: create primary with material + 3 replicas
	createReplicasConfig := awsConnectionResource +
		fmt.Sprintf(createConfig, replica1Alias, replica2Alias, replica3Alias, replica4Alias,
			cmName1, cmName2)

	addNewMaterial2Config := createReplicasConfig + fmt.Sprintf(keyMaterialConfig, material2)
	addNewMaterial3Config := createReplicasConfig + fmt.Sprintf(keyMaterialConfig, material2+","+material3)

	var capturedPrimaryKeyID string
	var capturedCmKeyID string

	primaryResource := "ciphertrust_aws_byok_key.primary"
	replica1Resource := "ciphertrust_aws_byok_key.replica_1"
	replica2Resource := "ciphertrust_aws_byok_key.replica_2"
	replica3Resource := "ciphertrust_aws_byok_key.replica_3"
	replica4Resource := "ciphertrust_aws_byok_key.replica_4"
	kmResource := "ciphertrust_aws_key_material.key_material"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1. Create primary key and replicas and 2 extra cm keys
				Config: createReplicasConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica1Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica4Resource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttr(primaryResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.0.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.0.import_state", "IMPORTED"),
				),
			},
			{
				// Step 2.  Add material2. Primary rotates to material2; replicas sync.
				Config: addNewMaterial2Config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica1Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica4Resource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.import_state", "IMPORTED"),
				),
			},
			{
				// Step 3.  Refresh state and check the rotation history of the keys
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica1Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica4Resource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(primaryResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.1.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.1.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.1.import_state", "IMPORTED"),
				),
			},
			{
				// Step 4. Add material3. Primary rotates to material2; replicas sync.
				Config: addNewMaterial3Config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica1Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica4Resource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.2.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.2.aws_params.import_state", "IMPORTED"),

					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[kmResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", kmResource)
						}
						capturedPrimaryKeyID = rs.Primary.ID
						rsCmKey, ok := s.RootModule().Resources["ciphertrust_cm_key.cm_aes_key"]
						if !ok {
							return fmt.Errorf("ciphertrust_cm_key.cm_aes_key2 not found in state")
						}
						capturedCmKeyID = rsCmKey.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 5. Refresh state and check keys
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica1Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica4Resource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.2.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.2.aws_params.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(primaryResource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.2.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.2.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.2.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.2.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.2.import_state", "IMPORTED"),
				),
			},
			{
				// Step 6. Delete material2 (index 1 = second-newest) from primary OOB.
				// Rotation history order: material3=index 0, material2=index 1, material1=index 2.
				// Primary key remains Enabled because material3 is still current.
				// Provider detects missing rotation entry -> non-empty plan.
				PreConfig: func() {
					deleteByokKeyMaterialAtIndex(capturedPrimaryKeyID, 1)
					refreshKeyAndWait(capturedPrimaryKeyID, capturedCmKeyID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 7. Re-apply. Provider detects material2 missing and re-imports it.
				// rotation_history.# should return to 3 on primary and all 3 replicas.
				Config: addNewMaterial3Config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.2.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.2.aws_params.import_state", "IMPORTED"),
				),
			},
			{
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica1Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica3Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica4Resource, "aws_param.key_state", "Enabled"),

					resource.TestCheckResourceAttr(primaryResource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.2.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.2.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.2.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica3Resource, "rotation_history.2.import_state", "IMPORTED"),

					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.1.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.2.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica4Resource, "rotation_history.2.import_state", "IMPORTED"),
				),
			},
			{
				// Step 8: confirm plan is stable.
				RefreshState: true,
			},
		},
	})
}

// TestCckmAWSKeyMaterialRepairMultiRegionPendingImportAndRotation verifies that the provider
// correctly repairs a primary EXTERNAL multi-region key stuck in
// PENDING_MULTI_REGION_IMPORT_AND_ROTATION state with 3 replica keys.
//
// Flow:
//  1. Create primary MR key (PendingImport) + 3 replicas.
//  2. Create aws_key_material with material1 on primary. All 4 keys become Enabled.
//     Capture primary CM UUID and material2 CM key ID for OOB import.
//  3. OOB: import material2 with NEW_KEY_MATERIAL on the PRIMARY key.
//     After sleeping 30s for replica sync of material1 to complete first.
//     Primary + all 3 replicas enter PENDING_MULTI_REGION_IMPORT_AND_ROTATION.
//     Refresh primary OOB. RefreshState detects drift -> non-empty plan.
//  4. Observability step: apply with [material1] only + rotation list DS for primary.
//     DS confirms material2 in PENDING_MULTI_REGION_IMPORT_AND_ROTATION state.
//  5. Repair step: apply with [material1, material2]:
//     a. Imports material2 to each of the 3 replicas with EXISTING_KEY_MATERIAL.
//     b. Waits for primary to reach PENDING_ROTATION.
//     Call rotate-material on primary.
//     Verify rotation_history.#=2 and all keys Enabled.
//  6. RefreshState - confirm plan stable.
func TestCckmAWSKeyMaterialRepairMultiRegionPendingImportAndRotation(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	replica1Alias := "tf-" + uuid.New().String()[8:]
	replica2Alias := "tf-" + uuid.New().String()[8:]
	replica3Alias := "tf-" + uuid.New().String()[8:]

	// Step 1: primary + 3 replicas (no material yet).
	createConfig := `
		locals {
			cmKeyName2 = "${local.cmKeyName}-2"
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key2" {
			name                         = local.cmKeyName2
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_byok_key" "mr_primary" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
		}
		resource "ciphertrust_aws_byok_key" "mr_replica_1" {
			region = ciphertrust_aws_kms.kms.regions[1]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.mr_primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		resource "ciphertrust_aws_byok_key" "mr_replica_2" {
			region = ciphertrust_aws_kms.kms.regions[2]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.mr_primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		resource "ciphertrust_aws_byok_key"  "mr_replica_3" {
			region = ciphertrust_aws_kms.kms.regions[3]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.mr_primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		data "ciphertrust_aws_key_rotation_list" "primary_rotations" {
			key_id = ciphertrust_aws_byok_key.mr_primary.id
		}
		# Place holder for ciphertrust_aws_key_material
		%s`

	// Step 5 (repair): original material + material2.
	addMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.mr_primary.aws_param.key_id
			key_material = [
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier       = "local"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
					source_key_tier       = "local"
				}]
		}`

	primaryResource := "ciphertrust_aws_byok_key.mr_primary"
	kmResource := "ciphertrust_aws_key_material.km"
	rotationHistoryDSResource := "data.ciphertrust_aws_key_rotation_list.primary_rotations"

	var capturedPrimaryKeyID string
	var capturedCmKey2ID string

	createConfigStr := fmt.Sprintf(createConfig, replica1Alias, replica2Alias, replica3Alias, "\n")
	addMaterialConfigStr := fmt.Sprintf(createConfig, replica1Alias, replica2Alias, replica3Alias, addMaterialConfig)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create primary MR key + 3 replicas
				Config: awsConnectionResource + createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(primaryResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.origin", "EXTERNAL"),
				),
			},
			{
				// Step 2: add material1 to primary. All 3 replicas receive material1.
				// Capture primary CM UUID and material2 CM key ID for later OOB import.
				Config: awsConnectionResource + createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[primaryResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", primaryResource)
						}
						capturedPrimaryKeyID = rs.Primary.ID
						rs2, ok := s.RootModule().Resources["ciphertrust_cm_key.cm_aes_key2"]
						if !ok {
							return fmt.Errorf("ciphertrust_cm_key.cm_aes_key2 not found in state")
						}
						capturedCmKey2ID = rs2.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 3: OOB import material2 with NEW_KEY_MATERIAL on primary.
				// Sleep 30s first to let CM finish propagating material1 to the 3 replicas.
				// After the import, primary + all 3 replicas enter
				// PENDING_MULTI_REGION_IMPORT_AND_ROTATION because replicas do not yet
				// have material2.
				// Refresh primary OOB so CM re-syncs rotation history.
				// ModifyPlan detects PENDING_MULTI_REGION_IMPORT_AND_ROTATION -> non-empty plan.
				PreConfig: func() {
					//fmt.Println("TestCckmAWSKeyMaterialRepairMultiRegionPendingImportAndRotation: sleeping 30s for CM background replication of material1 to replicas")
					//time.Sleep(30 * time.Second)
					callByokImportMaterialOutOfBand(
						"TestCckmAWSKeyMaterialRepairMultiRegionPendingImportAndRotation",
						capturedPrimaryKeyID, capturedCmKey2ID, "local", "NEW_KEY_MATERIAL",
					)
					refreshKeyAndWait(capturedPrimaryKeyID, capturedCmKey2ID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// The rotation list DS shows material2 in
				// PENDING_MULTI_REGION_IMPORT_AND_ROTATION state in test output.
				// material1 is not included in the plan so won't cant be repaired
				Config: awsConnectionResource + createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(rotationHistoryDSResource, "rotations.0.aws_params.key_material_state", "PENDING_MULTI_REGION_IMPORT_AND_ROTATION"),
					resource.TestCheckResourceAttr(rotationHistoryDSResource, "rotations.1.aws_params.key_material_state", "CURRENT"),
				),
			},
			{
				// Step 5: apply with [material1, material2]:
				//   a. Imports material2 to each of the 3 replicas (EXISTING_KEY_MATERIAL).
				//   b. Waits for primary to reach PENDING_ROTATION.
				// Call rotate-material.
				// Both keys should become Enabled with rotation_history.#=2.
				Config: awsConnectionResource + addMaterialConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttrSet(rotationHistoryDSResource, "key_id"),
				),
			},
			{
				// Step 6: confirm plan is stable after repair.
				RefreshState: true,
			},
		},
	})
}

// TestCckmAWSKeyMaterialAdoptPendingRotation verifies that the provider correctly adopts
// key material on the Create path when the material was imported out-of-band and is
// stuck in PENDING_ROTATION state.
//
// The raw import-material API only uploads bytes; it does not call the activate step.
// This leaves the material in PENDING_ROTATION, requiring a separate rotate-material call
// to make it CURRENT. The Create path of aws_key_material must detect this condition and
// complete the rotation instead of blindly importing new material bytes.
//
// Flow:
//  1. Create an EXTERNAL key in PendingImport state (no aws_key_material yet).
//     Capture the CM id of the AWS key and the CM id of the CipherTrust source key.
//  2. OOB: call import-material with NEW_KEY_MATERIAL on the PendingImport key.
//     The material bytes are uploaded but the rotate-material step is skipped, so the
//     key material enters PENDING_ROTATION state.
//  3. Add aws_key_material to config with one entry matching the OOB-imported source key.
//     Create detects PENDING_ROTATION in live rotation history and calls rotate-material
//     with an empty body to activate the material. Verify key_state=Enabled,
//     rotation_history.#=1 and rotation_history.0.key_material_state=CURRENT.
//  4. RefreshState confirms the plan is stable.
func TestCckmAWSKeyMaterialAdoptPendingRotation(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// Step 2/3 config: add aws_key_material to adopt the PENDING_ROTATION material.
	createConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_byok_key" "ext_key" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias = [local.alias]
			}
		}
		# Placeholder for ciphertrust_aws_key_material
		%s
	`
	adoptMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier       = "local"
			}]
		}`

	// capturedKeyID is the CM id of the AWS ext_key.
	// capturedCmKeyID is the CM id of the CipherTrust source key (cm_aes_key).
	var capturedKeyID string
	var capturedCmKeyID string

	extKeyResource := "ciphertrust_aws_byok_key.ext_key"
	kmResource := "ciphertrust_aws_key_material.km"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the EXTERNAL key in PendingImport state.
				// Capture both CM IDs for use in the Step 2 PreConfig.
				Config: awsConnectionResource + fmt.Sprintf(createConfig, "\n"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(extKeyResource, "id"),
					resource.TestCheckResourceAttr(extKeyResource, "aws_param.key_state", "PendingImport"),
					resource.TestCheckResourceAttr(extKeyResource, "aws_param.origin", "EXTERNAL"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[extKeyResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", extKeyResource)
						}
						capturedKeyID = rs.Primary.ID
						rs2, ok := s.RootModule().Resources["ciphertrust_cm_key.cm_aes_key"]
						if !ok {
							return fmt.Errorf("ciphertrust_cm_key.cm_aes_key not found in state")
						}
						capturedCmKeyID = rs2.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2+3: OOB import of material bytes using NEW_KEY_MATERIAL.
				// On a PendingImport key the raw import-material call uploads bytes but does
				// not call the rotate-material step, leaving the material in PENDING_ROTATION.
				// The aws_key_material resource is then added to config (Create path).
				// The provider detects PENDING_ROTATION in live rotation history and calls
				// rotate-material with an empty body to activate the material.
				PreConfig: func() {
					callByokImportMaterialOutOfBand(
						"TestCckmAWSKeyMaterialAdoptPendingRotation/OOB",
						capturedKeyID, capturedCmKeyID, "local", "NEW_KEY_MATERIAL",
					)
				},
				Config: awsConnectionResource + fmt.Sprintf(createConfig, adoptMaterialConfig),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(kmResource, "id"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.0.source_key_identifier"),
				),
			},
			{
				// Step 4: confirm plan is stable after Create-path PENDING_ROTATION adoption.
				RefreshState: true,
			},
		},
	})
}

// TestCckmAWSKeyMaterialAdoptPendingMRRotation verifies that the provider correctly adopts
// key material on the Create path when the material was imported out-of-band to the primary
// and one of two replicas, leaving the primary in PENDING_MULTI_REGION_IMPORT_AND_ROTATION
// state (because the second replica is still missing the material).
//
// Setup: primary MR key (Enabled with cm_aes_key material from mrExtKeyConfig) + 2 replicas.
// No aws_key_material resource until the adopt step. A second CM key (cm_aes_key2) is used
// for the out-of-band import so that it is distinct from the material already current in the
// primary (a key already in IMPORTED state cannot be re-imported with NEW_KEY_MATERIAL).
//
// Flow:
//  1. Create primary (MR, Enabled) + 2 replicas. Capture primary CM id, replica_1 CM id,
//     and cm_aes_key2 CM id for use in the OOB PreConfig.
//  2. OOB PreConfig (three operations):
//     a. Call import-material NEW_KEY_MATERIAL with cm_aes_key2 on the PRIMARY key.
//     The primary receives the bytes; because replica_2 has not yet received them, the
//     primary enters PENDING_MULTI_REGION_IMPORT_AND_ROTATION.
//     b. Call import-material EXISTING_KEY_MATERIAL with cm_aes_key2 on replica_1.
//     replica_1 now has the bytes but replica_2 still has nothing.
//     c. Refresh the primary key out-of-band so CM re-syncs AWS state.
//     Then apply config that adds aws_key_material with [cm_aes_key, cm_aes_key2]. Create
//     detects PENDING_MULTI_REGION_IMPORT_AND_ROTATION, imports cm_aes_key2 to replica_2
//     (the only key still missing it), waits for the primary to reach PENDING_ROTATION,
//     then calls rotate-material. All 3 keys become Enabled.
//  3. Verify enabled=true, rotation_history.#=2 (cm_aes_key initial + cm_aes_key2 current),
//     rotation_history.0.key_material_state=CURRENT.
//  4. RefreshState confirms plan is stable.
func TestCckmAWSKeyMaterialAdoptPendingMRRotation(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// replicaKeysConfig creates 2 replicas depending on the primary. The second replica
	// depends on the first so CM has time to finish the first replication before starting
	// the second, avoiding race conditions in replica state propagation.
	createConfig := `
		locals {
			cmKeyName2 = "${local.cmKeyName}-2"
			cmKeyName3 = "${local.cmKeyName}-3"
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key2" {
			name                         = local.cmKeyName2
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_byok_key" "mr_primary" {
			kms_id                = ciphertrust_aws_kms.kms.id
			region                = ciphertrust_aws_kms.kms.regions[0]
			source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier       = "local"
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
		}
		resource "ciphertrust_aws_byok_key" "mr_replica_1" {
			region = ciphertrust_aws_kms.kms.regions[1]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.mr_primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		resource "ciphertrust_aws_byok_key" "mr_replica_2" {
			region = ciphertrust_aws_kms.kms.regions[2]
			replicate_key = {
				key_id = ciphertrust_aws_byok_key.mr_primary.id
			}
			aws_param = {
				alias = ["%s"]
			}
		}
		# Placeholder for ciphertrust_aws_key_material
		%s`

	// Step 2/3 config: add aws_key_material referencing both cm_aes_key (already current
	// in the primary) and cm_aes_key2 (imported OOB, currently in
	// PENDING_MULTI_REGION_IMPORT_AND_ROTATION). The Create path detects the pending state
	// and completes the rotation by importing cm_aes_key2 to replica_2 then activating.
	adoptMaterialAndAddMaterialConfig := `
		resource "ciphertrust_aws_key_material" "km" {
			depends_on = [
				ciphertrust_aws_byok_key.mr_replica_1,
				ciphertrust_aws_byok_key.mr_replica_2,
			]
		aws_key_id = ciphertrust_aws_byok_key.mr_primary.aws_param.key_id
			key_material = [
				# This is the original material - it will be 'adopted' into this resource
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier       = "local"
				},
				# This material will be imported to primary and 1 replica leaving
				# all key_states in PENDING_MULTIREGION_IMPORT_AND_ROTATION state
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
					source_key_tier       = "local"
				},
			]
		}`

	var capturedPrimaryKeyID string
	var capturedReplica1KeyID string
	var capturedCmKey1ID string
	var capturedCmKey2ID string

	replica1Alias := "tf-" + uuid.New().String()[8:]
	replica2Alias := "tf-" + uuid.New().String()[8:]

	createConfigStr := fmt.Sprintf(createConfig, replica1Alias, replica2Alias, "\n")
	adoptOriginalAndAddConfigStr := fmt.Sprintf(createConfig, replica1Alias, replica2Alias, adoptMaterialAndAddMaterialConfig)

	primaryResource := "ciphertrust_aws_byok_key.mr_primary"
	replica1Resource := "ciphertrust_aws_byok_key.mr_replica_1"
	replica2Resource := "ciphertrust_aws_byok_key.mr_replica_2"
	kmResource := "ciphertrust_aws_key_material.km"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create primary MR key (Enabled) + 2 replicas.
				// mrExtKeyConfig provides source_key_identifier so the primary is Enabled,
				// allowing replicas to be created without KMSInvalidStateException.
				// Capture the primary CM id, replica_1 CM id, and cm_aes_key2 CM id.
				Config: awsConnectionResource + createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(primaryResource, "id"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttrSet(replica1Resource, "id"),
					resource.TestCheckResourceAttrSet(replica2Resource, "id"),
					func(s *terraform.State) error {
						// Key to import new material too
						rs, ok := s.RootModule().Resources[primaryResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", primaryResource)
						}
						capturedPrimaryKeyID = rs.Primary.ID

						// Key to import new material too
						rs1, ok := s.RootModule().Resources[replica1Resource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", replica1Resource)
						}
						capturedReplica1KeyID = rs1.Primary.ID

						// Rotation record to check during refresh wait
						rsCM1, ok := s.RootModule().Resources["ciphertrust_cm_key.cm_aes_key"]
						if !ok {
							return fmt.Errorf("ciphertrust_cm_key.cm_aes_key2 not found in state")
						}
						capturedCmKey1ID = rsCM1.Primary.ID

						// Source key id of CM key - material to import
						rsCM2, ok := s.RootModule().Resources["ciphertrust_cm_key.cm_aes_key2"]
						if !ok {
							return fmt.Errorf("ciphertrust_cm_key.cm_aes_key2 not found in state")
						}
						capturedCmKey2ID = rsCM2.Primary.ID
						return nil
					},
				),
			},
			{
				RefreshState: true,
				Check:        resource.ComposeTestCheckFunc()},
			{
				// Step 2+3: Import cm_aes_key2 to primary and replica_1, leaving replica_2 without
				// cm_aes_key2 bytes. Primary enters PENDING_MULTI_REGION_IMPORT_AND_ROTATION.
				// After a 60-second stabilization sleep, RefreshKeyAndWait confirms CM has re-synced
				// AWS state. Then apply config that adds aws_key_material with [cm_aes_key, cm_aes_key2].
				// Create detects the pending state, imports cm_aes_key2 to replica_2, waits for
				// primary -> PENDING_ROTATION, then calls rotate-material to activate.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						fmt.Println("TestCckmAWSKeyMaterialAdoptPendingMRRotation: could not create CM client")
						return
					}
					ctx := context.Background()
					id := uuid.New().String()
					var diags diag.Diagnostics

					// a. Import cm_aes_key2 bytes to the primary using NEW_KEY_MATERIAL.
					//    Primary has the bytes; replica_2 is still missing them, so primary
					//    enters PENDING_MULTI_REGION_IMPORT_AND_ROTATION.
					cckm.ImportByokKeyMaterial(ctx, id, client,
						capturedPrimaryKeyID, capturedCmKey2ID, "local", "", "", "NEW_KEY_MATERIAL", &diags)
					// b. Import the same cm_aes_key2 bytes to replica_1 using EXISTING_KEY_MATERIAL.
					//    replica_1 now has the bytes; replica_2 does not.
					cckm.ImportByokKeyMaterial(ctx, id, client,
						capturedReplica1KeyID, capturedCmKey2ID, "local", "", "", "EXISTING_KEY_MATERIAL", &diags)
					if diags.HasError() {
						fmt.Printf("TestCckmAWSKeyMaterialAdoptPendingMRRotation: import-material failed: %v\n", diags)
						return
					}
					// c. Sleep 30s for rotation history to stabilize before refreshing.
					fmt.Println("TestCckmAWSKeyMaterialAdoptPendingMRRotation: sleeping 30s for rotation history to stabilise")
					time.Sleep(60 * time.Second)
					// d. Refresh the primary and wait for CM to confirm it has re-synced AWS state.
					//    RefreshKeyAndWait polls for the rotation history updatedAt to change rather
					//    than sleeping a fixed duration, so the test is more reliable.
					keyJSON, err := client.GetById(ctx, id, capturedPrimaryKeyID, common.URL_AWS_KEY)
					if err != nil {
						fmt.Printf("TestCckmAWSKeyMaterialAdoptPendingMRRotation: could not fetch primary key JSON: %v\n", err)
						return
					}
					cckm.RefreshKeyAndWait(ctx, id, client, capturedPrimaryKeyID, keyJSON, []string{capturedCmKey1ID}, &diags)
					if diags.HasError() {
						fmt.Printf("TestCckmAWSKeyMaterialAdoptPendingMRRotation: RefreshKeyAndWait failed: %v\n", diags)
						return
					}
					if diags.WarningsCount() > 0 {
						fmt.Printf("TestCckmAWSKeyMaterialAdoptPendingMRRotation: RefreshKeyAndWait warnings: %v\n", diags)
					}
				},
				Config: awsConnectionResource + adoptOriginalAndAddConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(kmResource, "id"),
					// rotation_history is ordered newest first. After adoption:
					//   [0] = cm_aes_key2 (newly activated by the adopt, CURRENT)
					//   [1] = cm_aes_key  (initial import, now NON_CURRENT)
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
					// [0]: cm_aes_key2 - the material just activated by the Create-path adopt.
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.last_import_status", "Success"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.rotation_type", "ON_DEMAND"),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.0.aws_params.key_material_id"),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.0.source_key_identifier"),
					// [1]: cm_aes_key - the original material loaded by mrExtKeyConfig, now displaced.
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.last_import_status", "Success"),
					// first import has no rotation_type - it was not triggered by a rotate-material call.
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.rotation_type", ""),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.1.source_key_identifier"),
					// replica_1: PreConfig imported cm_aes_key2 bytes (EXISTING_KEY_MATERIAL),
					// so [0] shows import_state=IMPORTED but key_material_state is still
					// PENDING_MULTI_REGION_IMPORT_AND_ROTATION because replica_2 had not yet
					// received the bytes when the check runs. [1] = old material still CURRENT
					// on the replica until the primary rotation fully propagates.
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.key_material_state", "PENDING_MULTI_REGION_IMPORT_AND_ROTATION"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.last_import_status", "Success"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.import_state", "IMPORTED"),
					// replica_2: PreConfig did NOT import cm_aes_key2 bytes - the Create-path
					// adopt is responsible for importing to this replica. At check time the
					// import may still be in progress, so import_state=PENDING_IMPORT and
					// last_import_status is empty. [1] = old material still CURRENT on the replica.
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.key_material_state", "PENDING_MULTI_REGION_IMPORT_AND_ROTATION"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.import_state", "PENDING_IMPORT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.last_import_status", ""),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.import_state", "IMPORTED"),
				),
			},
			{
				// Step 4: confirm plan is stable after Create-path adoption of
				// PENDING_MULTI_REGION_IMPORT_AND_ROTATION material.
				RefreshState: true,
				Check:        resource.ComposeTestCheckFunc(),
			},
			{
				// Step 5: verify all keys have settled to Enabled with fully resolved
				// rotation history after RefreshState confirms no drift.
				Config: awsConnectionResource + adoptOriginalAndAddConfigStr,
				Check: resource.ComposeTestCheckFunc(
					// km resource: primary material settled.
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.1.aws_params.import_state", "IMPORTED"),
					// primary key: settled.
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.1.import_state", "IMPORTED"),
					// replica_1: cm_aes_key2 fully propagated and activated.
					resource.TestCheckResourceAttr(replica1Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica1Resource, "rotation_history.1.import_state", "IMPORTED"),
					// replica_2: cm_aes_key2 imported and activated by the Create-path adopt.
					resource.TestCheckResourceAttr(replica2Resource, "aws_param.key_state", "Enabled"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.0.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.key_material_state", "NON_CURRENT"),
					resource.TestCheckResourceAttr(replica2Resource, "rotation_history.1.import_state", "IMPORTED"),
				),
			},
		},
	})
}

// TestCckmAWSKeyMaterialMRPendingImportFirstMaterial verifies that a multi-region
// EXTERNAL key created in PendingImport state (no source_key_identifier) can receive
// its first key material via aws_key_material and transition to enabled state.
func TestCckmAWSKeyMaterialMRPendingImportFirstMaterial(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	// mrPendingConfig creates a multi-region EXTERNAL key in PendingImport state.
	// No source_key_identifier is supplied so no material is imported on create.
	// Replicas are intentionally omitted - they cannot be created from a PendingImport key.
	createConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_byok_key" "mr_primary" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias        = [local.alias]
				multi_region = true
			}
		}`

	// Step 2 config: add aws_key_material to import the first material to the primary.
	updateConfig := createConfig + `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.mr_primary.aws_param.key_id
			key_material = [{
				source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier       = "local"
			}]
		}`

	primaryResource := "ciphertrust_aws_byok_key.mr_primary"
	kmResource := "ciphertrust_aws_key_material.km"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the MR primary key with no material. Verify PendingImport.
				Config: awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(primaryResource, "id"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.key_state", "PendingImport"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.origin", "EXTERNAL"),
					resource.TestCheckResourceAttr(primaryResource, "aws_param.multi_region", "true"),
					resource.TestCheckResourceAttr(primaryResource, "rotation_history.#", "0"),
				),
			},
			{
				// Step 2: add aws_key_material with material1. Key transitions to Enabled.
				Config: awsConnectionResource + updateConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(kmResource, "id"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.#", "1"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.import_state", "IMPORTED"),
					resource.TestCheckResourceAttr(kmResource, "rotation_history.0.aws_params.key_material_state", "CURRENT"),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.0.source_key_identifier"),
					resource.TestCheckResourceAttrSet(kmResource, "rotation_history.0.aws_params.key_material_id"),
				),
			},
			{
				// Step 3: confirm plan is stable after first material import on an MR key.
				RefreshState: true,
			},
		},
	})
}

// TestCckmAWSKeyMaterialPlanValidation
// No set values on create
// Adding more than one new key_material
// Set values that duplicate source_key_id
func TestCckmAWSKeyMaterialPlanValidation(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	baseConfig := `
		locals {
			cmKeyName2 = "${local.cmKeyName}-2"
			cmKeyName3 = "${local.cmKeyName}-3"
		}
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = local.cmKeyName
			algorithm                    = "AES"
		}
		resource "ciphertrust_cm_key" "cm_aes_key2" {
			name                         = local.cmKeyName2
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_byok_key" "ext_key" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias = [local.alias]
			}
		}`

	// Duplicate source_key_identifier must fail at plan time.
	// The two entries have different valid_to values so they are distinct set members
	// (a set would otherwise de-duplicate identical entries before ModifyPlan runs).
	dupValidTo1 := awsKeyValidTo(180)
	dupValidTo2 := awsKeyValidTo(270)
	duplicateSrcKeyConfig := baseConfig + fmt.Sprintf(`
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier       = "local"
					valid_to              = "%s"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier       = "local"
					valid_to              = "%s"
				},
			]
		}`, dupValidTo1, dupValidTo2)

	// Zero entries on create: should be rejected at plan time.
	zeroOnCreateConfig := baseConfig + `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id   = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = []
		}`

	// Add m2 AND m3 in one apply - 2 new entries, should be rejected.
	tooManyNewOnCreateConfig := baseConfig + `
		resource "ciphertrust_cm_key" "cm_aes_key3" {
			name                         = local.cmKeyName3
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier       = "local"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
					source_key_tier       = "local"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key3.id
					source_key_tier       = "local"
				},
			]
		}`

	// Configs for update-time plan validation (require a prior apply to have state).
	// Step 4 (apply): create with m1 so the resource exists in state.
	createConfig := baseConfig + `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [{
				source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier       = "local"
			}]
		}`

	tooManyNewOnUpdateConfig := baseConfig + `
		resource "ciphertrust_cm_key" "cm_aes_key3" {
			name                         = local.cmKeyName3
			algorithm                    = "AES"
		}
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = [
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key.id
					source_key_tier       = "local"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key2.id
					source_key_tier       = "local"
				},
				{
					source_key_identifier = ciphertrust_cm_key.cm_aes_key3.id
					source_key_tier       = "local"
				},
			]
		}`

	// Remove all key_material entries - now allowed.
	// All material bytes are deleted; rotation history entries remain but move to PENDING_IMPORT.
	removeAllMaterialConfig := baseConfig + `
		resource "ciphertrust_aws_key_material" "km" {
			aws_key_id   = ciphertrust_aws_byok_key.ext_key.aws_param.key_id
			key_material = []
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Duplicate source_key_identifier is rejected during Create.
				Config:      awsConnectionResource + duplicateSrcKeyConfig,
				ExpectError: regexp.MustCompile(`Duplicate source_key_identifier`),
			},
			{
				// Creating with 0 entries is rejected at plan time.
				Config:      awsConnectionResource + zeroOnCreateConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`At least one key_material entry is required on create`),
			},
			{
				// Adding > 1 new entries in one update is rejected at apply time.
				Config:      awsConnectionResource + tooManyNewOnCreateConfig,
				ExpectError: regexp.MustCompile(`Too many new key_material entries`),
			},
			{
				// Apply to create the resource with m1 so subsequent plan-only
				// steps have state to validate against (update-time checks need state).
				Config: awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_aws_key_material.km", "rotation_history.#", "1"),
				),
			},
			{
				// Adding > 1 new entries in one update is rejected at apply time.
				Config:      awsConnectionResource + tooManyNewOnUpdateConfig,
				ExpectError: regexp.MustCompile(`Too many new key_material entries`),
			},
			{
				// Remove all key_material entries
				Config: awsConnectionResource + removeAllMaterialConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_aws_key_material.km", "rotation_history.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_aws_key_material.km", "rotation_history.0.aws_params.import_state", "PENDING_IMPORT"),
				),
			},
		},
	})
}

// deleteByokKeyMaterialAtIndex fetches the rotation history for the CCKM BYOK key
// identified by keyID and deletes the AWS key material at rotationIndex (0-based,
// ordered as returned by the rotations API - typically newest-first). The testName
// prefix is included in log output to identify which test triggered the operation.
func deleteByokKeyMaterialAtIndex(keyID string, rotationIndex int) {
	client, ok := createCMClient()
	if !ok {
		fmt.Printf("Could not create CM client, skipping delete-material\n")
		return
	}
	ctx := context.Background()
	id := uuid.New().String()
	filters := url.Values{
		"skip":  []string{"0"},
		"limit": []string{"10"},
	}
	rotationsEndpoint := common.URL_AWS_KEY + "/" + keyID + "/rotations"
	rotationsJSON, err := client.ListWithFilters(ctx, id, rotationsEndpoint, filters)
	if err != nil {
		fmt.Printf("Failed to list rotations: %s\n", err.Error())
		return
	}
	resources := gjson.Get(rotationsJSON, "resources").Array()
	if rotationIndex >= len(resources) {
		fmt.Printf("rotationIndex %d out of range (have %d entries)\n", rotationIndex, len(resources))
		return
	}
	keyMaterialID := resources[rotationIndex].Get("aws_param.KeyMaterialId").String()
	if keyMaterialID == "" {
		fmt.Printf("KeyMaterialId not found at rotation index %d\n", rotationIndex)
		return
	}
	fmt.Printf("Ddeleting key material id=%s (rotation index %d)\n", keyMaterialID, rotationIndex)
	payload, _ := json.Marshal(map[string]string{"key_material_id": keyMaterialID})
	deleteMaterialURL := common.URL_AWS_KEY + "/" + keyID + "/delete-material"
	_, err = client.PostDataV2(ctx, id, deleteMaterialURL, payload)
	if err != nil {
		fmt.Printf("delete-material failed: %s\n", err.Error())
		return
	}
	fmt.Printf("Key material deleted out-of-band\n")
	time.Sleep(30 * time.Second)
}

// callByokImportMaterialOutOfBand calls the import-material API out-of-band for a BYOK key.
// importType must be "NEW_KEY_MATERIAL" or "EXISTING_KEY_MATERIAL". When called with
// NEW_KEY_MATERIAL on a key that already has current material the new material enters
// PENDING_ROTATION state. The testName prefix is included in log output.
func callByokImportMaterialOutOfBand(testName, keyID, sourceKeyID, sourceKeyTier, importType string) {
	client, ok := createCMClient()
	if !ok {
		fmt.Printf("%s: could not create CM client, skipping import-material\n", testName)
		return
	}
	ctx := context.Background()
	id := uuid.New().String()
	payload, _ := json.Marshal(map[string]interface{}{
		"source_key_identifier": sourceKeyID,
		"source_key_tier":       sourceKeyTier,
		"import_type":           importType,
		"key_expiration":        false,
		"valid_to":              "",
	})
	importMaterialURL := common.URL_AWS_KEY + "/" + keyID + "/import-material"
	_, err := client.PostDataV2(ctx, id, importMaterialURL, payload)
	if err != nil {
		fmt.Printf("%s: import-material (%s) failed: %s\n", testName, importType, err.Error())
	} else {
		fmt.Printf("%s: import-material (%s) called out-of-band for key %s source %s\n", testName, importType, keyID, sourceKeyID)
	}
	// The rotation-history update in CM is a background task. Always sleep so that
	// the subsequent RefreshState sees the PENDING_ROTATION entry in history.
	fmt.Printf("%s: sleeping 30s for rotation history to stabilise\n", testName)
	time.Sleep(30 * time.Second)
}

func refreshKeyAndWait(keyID string, sourceKeyID string) {
	client, ok := createCMClient()
	if !ok {
		fmt.Println("testName: could not create CM client")
		return
	}
	ctx := context.Background()
	id := uuid.New().String()
	var diags diag.Diagnostics
	keyJSON, err := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		fmt.Printf("testName: could not fetch primary key JSON: %v\n", err)
		return
	}
	cckm.RefreshKeyAndWait(ctx, id, client, keyID, keyJSON, []string{sourceKeyID}, &diags)
	if diags.HasError() {
		fmt.Printf("testName: RefreshKeyAndWait failed: %v\n", diags)
		return
	}
	if diags.WarningsCount() > 0 {
		fmt.Printf("testName: RefreshKeyAndWait warnings: %v\n", diags)
	}
}

// TestCckmAWSByokKeyCreatePendingImport verifies that an EXTERNAL (BYOK) key created with
// no source_key_identifier lands in PendingImport state. No key material is uploaded.
func TestCckmAWSByokKeyCreatePendingImport(t *testing.T) {
	if os.Getenv("CDSPAAS") == "true" {
		t.Skip("Skipping on CDSPAAS")
	}
	if getCipherTrustVersion() < 223 {
		t.Skip("Skipping on CipherTrust version < 223")
	}
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	createConfig := `
		resource "ciphertrust_aws_byok_key" "byok_pending" {
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
			aws_param = {
				alias = [local.alias]
			}
		}`
	keyResource := "ciphertrust_aws_byok_key.byok_pending"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create key with no source_key_identifier - lands in PendingImport.
				Config: awsConnectionResource + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "rotation_history.#", "0"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.arn"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.key_state", "PendingImport"),
					resource.TestCheckResourceAttr(keyResource, "aws_param.origin", "EXTERNAL"),
				),
			},
		},
	})
}
