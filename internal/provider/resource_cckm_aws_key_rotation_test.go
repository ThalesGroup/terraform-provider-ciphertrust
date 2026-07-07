package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCckmAWSKeyRotationNative verifies that rotating a native SYMMETRIC_DEFAULT AWS key
// via ciphertrust_aws_key_rotation succeeds. The rotation resource calls the AWS
// rotate-material API and records the operation in Terraform state.
//
// Step 1: Create a native key and request the first on-demand rotation.
//
//	Verify the rotation resource is populated and rotation_history has 1 entry.
//
// Step 2: Change the trigger value to request a second rotation (resource replacement).
//
//	Verify rotation_history now has 2 entries and that the native key itself
//	reports a current_key_material_id (only populated after at least one rotation).
//
// Note: ciphertrust_aws_key_rotation only supports native (AWS_KMS origin) symmetric keys.
//
//	Rotation of EXTERNAL (BYOK) keys is managed via ciphertrust_aws_byok_key and
//	ciphertrust_aws_key_material; their rotation_history fields are tested in
//	resource_cckm_aws_byok_key_test.go and resource_cckm_aws_key_material_test.go.
func TestCckmAWSKeyRotationNative(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	if getCipherTrustVersion() < 221 {
		t.Skip("Skipping on CipherTrust version < 221")
	}

	nativeKeyConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			aws_param = {
				alias                    = [local.alias]
				customer_master_key_spec = "SYMMETRIC_DEFAULT"
				description              = "key rotation test"
				key_usage                = "ENCRYPT_DECRYPT"
			}
			kms_id = ciphertrust_aws_kms.kms.id
			region = ciphertrust_aws_kms.kms.regions[0]
		}
		# Place holder for ciphertrust_aws_key_rotation
		%s`

	// nativeKeyConfig builds a config with a SYMMETRIC_DEFAULT native key and an
	// aws_key_rotation resource whose trigger value controls when a rotation fires.
	rotationConfig := `
		resource "ciphertrust_aws_key_rotation" "rotate" {
			key_id  = ciphertrust_aws_key.native_key.id
			trigger = "%s"
		}`

	keyResource := "ciphertrust_aws_key.native_key"
	rotationListResource := "ciphertrust_aws_key_rotation.rotate"

	createConfigStr := fmt.Sprintf(nativeKeyConfig, "\n")
	rotationConfigStr1 := fmt.Sprintf(nativeKeyConfig, fmt.Sprintf(rotationConfig, "rotation-1"))
	rotationConfigStr2 := fmt.Sprintf(nativeKeyConfig, fmt.Sprintf(rotationConfig, "rotation-2"))

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create no rotations
				Config: awsConnectionResource + createConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(keyResource, "aws_param.key_id"),
					// At this stage there may or may be 0 or 1 rotations in rotation_history
					// The key's current_key_material id may or may not be set before create returns
				),
			},
			{
				// Step 1: first rotation.
				Config: awsConnectionResource + rotationConfigStr1,
				Check: resource.ComposeTestCheckFunc(
					// Rotation resource identity.
					resource.TestCheckResourceAttrSet(rotationListResource, "id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "key_id"),
					// Now the original rotation and the new rotation should be in the history
					resource.TestCheckResourceAttr(rotationListResource, "rotation_history.#", "2"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.created_at"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.local_key_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.kms_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.key_material_origin"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.aws_params.rotation_type"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.aws_params.key_material_state"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.aws_params.key_material_id"),

					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.created_at"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.local_key_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.kms_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.key_material_origin"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.aws_params.key_material_state"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.aws_params.key_material_id"),
				),
			},
			{
				// Step 2: second rotation - change trigger causes resource replacement
				// which fires another rotate-material call.
				Config: awsConnectionResource + rotationConfigStr2,
				Check: resource.ComposeTestCheckFunc(
					// Rotation resource identity.
					resource.TestCheckResourceAttrSet(rotationListResource, "id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "key_id"),
					// Now the original rotation and the 2 new rotations should be in the history
					resource.TestCheckResourceAttr(rotationListResource, "rotation_history.#", "3"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.created_at"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.local_key_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.kms_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.key_material_origin"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.aws_params.rotation_type"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.aws_params.key_material_state"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.0.aws_params.key_material_id"),

					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.created_at"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.local_key_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.kms_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.key_material_origin"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.aws_params.rotation_type"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.aws_params.key_material_state"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.1.aws_params.key_material_id"),

					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.2.id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.2.created_at"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.2.local_key_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.2.kms_id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.2.key_material_origin"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.2.aws_params.key_material_state"),
					resource.TestCheckResourceAttrSet(rotationListResource, "rotation_history.2.aws_params.key_material_id"),
				),
			},
		},
	})
}
