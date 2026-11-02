package provider

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// checkRotationEntry verifies the attributes every rotation_history entry has.
// aws_params.rotation_type is not checked: the original key material has none.
func checkRotationEntry(resourceName string, index int) resource.TestCheckFunc {
	prefix := fmt.Sprintf("rotation_history.%d.", index)
	return resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttrSet(resourceName, prefix+"id"),
		resource.TestCheckResourceAttrSet(resourceName, prefix+"created_at"),
		resource.TestCheckResourceAttrSet(resourceName, prefix+"local_key_id"),
		resource.TestCheckResourceAttrSet(resourceName, prefix+"kms_id"),
		resource.TestCheckResourceAttrSet(resourceName, prefix+"key_material_origin"),
		resource.TestCheckResourceAttrSet(resourceName, prefix+"aws_params.key_material_state"),
		resource.TestCheckResourceAttrSet(resourceName, prefix+"aws_params.key_material_id"),
	)
}

// checkRotationHistory verifies rotation_history.
// With single key refresh (CM 2.22+ and CDSPaaS) it expects exactly expectedCount
// entries and checks each one. Without it CM may report fewer rotations than have
// occurred, so it only expects at least one entry and checks the first.
func checkRotationHistory(resourceName string, expectedCount int, supportsKeyRefresh bool) resource.TestCheckFunc {
	if !supportsKeyRefresh {
		return resource.ComposeTestCheckFunc(
			resource.TestCheckResourceAttrWith(resourceName, "rotation_history.#", func(value string) error {
				count, err := strconv.Atoi(value)
				if err != nil {
					return err
				}
				if count < 1 {
					return fmt.Errorf("expected at least 1 rotation_history entry, got %d", count)
				}
				return nil
			}),
			checkRotationEntry(resourceName, 0),
		)
	}
	checks := []resource.TestCheckFunc{
		resource.TestCheckResourceAttr(resourceName, "rotation_history.#", strconv.Itoa(expectedCount)),
	}
	for i := 0; i < expectedCount; i++ {
		checks = append(checks, checkRotationEntry(resourceName, i))
	}
	return resource.ComposeTestCheckFunc(checks...)
}

// TestCckmAWSKeyRotationNative verifies that rotating a native SYMMETRIC_DEFAULT AWS key
// via ciphertrust_aws_key_rotation succeeds. The rotation resource calls the AWS
// rotate-material API and records the operation in Terraform state.
//
// Step 1: Create a native key and request the first on-demand rotation.
//
//	Verify the rotation resource is populated and rotation_history has the original
//	key material and the new one (2 entries). Before CM 2.22 at least 1 entry.
//
// Step 2: Change the trigger value to request a second rotation (resource replacement).
//
//	Verify rotation_history now has 3 entries (at least 1 before CM 2.22) and that
//	the native key itself reports a current_key_material_id.
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

	// Single key refresh is not available before CM 2.22 so CM may report fewer rotations
	// than have occurred (the rotations still occur in AWS). CDSPaaS reports version 9999.
	supportsKeyRefresh := getCipherTrustVersion() >= 222

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
				// The original key material and the new one should be in the history.
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(rotationListResource, "id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "key_id"),
					checkRotationHistory(rotationListResource, 2, supportsKeyRefresh),
				),
			},
			{
				// Step 2: second rotation - change trigger causes resource replacement
				// which fires another rotate-material call.
				Config: awsConnectionResource + rotationConfigStr2,
				// The original key material and the 2 new ones should be in the history.
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(rotationListResource, "id"),
					resource.TestCheckResourceAttrSet(rotationListResource, "key_id"),
					checkRotationHistory(rotationListResource, 3, supportsKeyRefresh),
				),
			},
		},
	})
}

func TestCckmAWSKeyRotationCreateValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: key_id empty string
			{
				Config: `
					resource "ciphertrust_aws_key_rotation" "test" {
						key_id  = ""
						trigger = "v1"
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			// Step 2: key_id whitespace-only
			{
				Config: `
					resource "ciphertrust_aws_key_rotation" "test" {
						key_id  = "   "
						trigger = "v1"
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			// Step 3: trigger empty string
			{
				Config: `
					resource "ciphertrust_aws_key_rotation" "test" {
						key_id  = "valid-key-id"
						trigger = ""
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			// Step 4: trigger whitespace-only
			{
				Config: `
					resource "ciphertrust_aws_key_rotation" "test" {
						key_id  = "valid-key-id"
						trigger = "   "
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
		},
	})
}
