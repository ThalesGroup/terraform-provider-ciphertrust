package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

var _ = regexp.MustCompile

// initCckmOCITest builds the Terraform resource configuration used as a shared setup by most CCKM OCI
// tests. It creates an OCI connection and registers an OCI vault, exposing them as Terraform resources
// that each test can embed in its own config. Skips the test if the required OCI environment variables
// are not set.
func initCckmOCITest(t *testing.T) string {

	keyFile := os.Getenv("CCKM_OCI_KEY_FILE")
	pubKeyFP := os.Getenv("CCKM_OCI_FINGERPRINT")
	region := os.Getenv("CCKM_OCI_REGION")
	tenancyOCID := os.Getenv("CCKM_OCI_CONN_TENANCY")
	userOCID := os.Getenv("CCKM_OCI_USER")
	vaultOCID := os.Getenv("CCKM_OCI_VAULT")

	ok := keyFile != "" && pubKeyFP != "" && region != "" && tenancyOCID != "" && userOCID != "" /*&& compartmentOCID != "" */ && vaultOCID != ""
	if !ok {
		t.Skip("Failed to get OCI connection environment variables")
	}
	name := "tf-" + uuid.New().String()[:8]
	config := `
		locals {
			vault_ocid          = "%s"
			region              = "%s"
			cm_key_usage_mask   = %d
		}
		resource "ciphertrust_oci_connection" "oci_connection" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}
		resource "ciphertrust_oci_vault" "vault" {
			connection_id = ciphertrust_oci_connection.oci_connection.id
			vault_id      = local.vault_ocid
			region        = local.region
		}`
	resourceStr := fmt.Sprintf(config,
		vaultOCID, region, cmKeyUsageCryptoOps, keyFile, name, pubKeyFP, region, tenancyOCID, userOCID)
	return resourceStr
}

func TestCckmOCIKeysAndVersionsNative(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	localsConfig := `locals {
		oci_key_name        = "tf-%s"
		oci_key_name_update = "tf-%s"
	}`

	localsResource := fmt.Sprintf(localsConfig, uuid.New().String()[:8], uuid.New().String()[:8])

	createConfig := `
		%s
		%s

		# Create a native OCI key
		resource "ciphertrust_oci_key" "rsa" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name                       = local.oci_key_name
			schedule_for_deletion_days = 8
			vault                      = %s
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "version" {
			cckm_key_id                = %s
			schedule_for_deletion_days = 8
		}

		# List the key
		data "ciphertrust_oci_key_list" "keys" {
			depends_on = [ciphertrust_oci_key_version.version]
			filters = {
				key_name = ciphertrust_oci_key.rsa.name
			}
		}

		# List the key's versions
		data "ciphertrust_oci_key_version_list" "versions" {
			key_id = ciphertrust_oci_key.rsa.id
			depends_on = [ciphertrust_oci_key_version.version]
		}`

	updateConfig := `
		%s
		%s

		resource "ciphertrust_oci_key" "rsa" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name            = local.oci_key_name_update
			vault           = ciphertrust_oci_vault.vault.id
		}

		resource "ciphertrust_oci_key_version" "version" {
			cckm_key_id = ciphertrust_oci_key.rsa.id
		}

		data "ciphertrust_oci_key_list" "keys" {
			depends_on = [ciphertrust_oci_key_version.version]
			filters = {
				key_name = ciphertrust_oci_key.rsa.name
			}
		}

		data "ciphertrust_oci_key_version_list" "versions" {
			key_id = ciphertrust_oci_key.rsa.id
			depends_on = [ciphertrust_oci_key_version.version]
		}`

	keyResource := "ciphertrust_oci_key.rsa"
	versionResource := "ciphertrust_oci_key_version.version"
	keysDataSource := "data.ciphertrust_oci_key_list.keys"
	versionDataSource := "data.ciphertrust_oci_key_version_list.versions"

	createResourceStr := fmt.Sprintf(createConfig, localsResource, connectionResource,
		"ciphertrust_oci_vault.vault.id", "ciphertrust_oci_key.rsa.id")
	modifyKeyConfigStr := fmt.Sprintf(createConfig, localsResource, connectionResource,
		`"tf-fake-vault-id"`, "ciphertrust_oci_key.rsa.id")
	modifyVersionConfigStr := fmt.Sprintf(createConfig, localsResource, connectionResource,
		"ciphertrust_oci_vault.vault.id", `"tf-fake-key-id"`)
	updateResourceStr := fmt.Sprintf(updateConfig, localsResource, connectionResource)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.algorithm", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.length", "256"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
					resource.TestCheckResourceAttrSet(keyResource, "oci_key_params.key_id"),
					resource.TestCheckResourceAttrSet(keyResource, "vault_id"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "8"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.vault_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.key_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "8"),
					// Key list data source
					resource.TestCheckResourceAttr(keysDataSource, "keys.#", "1"),
					resource.TestCheckResourceAttr(keysDataSource, "matched", "1"),
					resource.TestCheckResourceAttrPair(keysDataSource, "keys.0.id", keyResource, "id"),
					resource.TestCheckResourceAttr(keysDataSource, "keys.0.oci_key_params.algorithm", "RSA"),
					resource.TestCheckResourceAttr(keysDataSource, "keys.0.oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keysDataSource, "keys.0.oci_key_params.length", "256"),
					// Key version list data source
					resource.TestCheckResourceAttr(versionDataSource, "versions.#", "2"),
					resource.TestCheckResourceAttr(versionDataSource, "matched", "2"),
					resource.TestCheckResourceAttrSet(versionDataSource, "versions.0.id"),
				),
			},
			{
				RefreshState: true,
			},
			{
				ResourceName:            keyResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreOCIKey,
			},
			{
				ResourceName:      versionResource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"schedule_for_deletion_days",
				},
				ImportStateIdFunc: getOCIKeyVersionID(keyResource, versionResource),
			},
			{
				Config: updateResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.algorithm", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "schedule_for_deletion_days", "8"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttr(versionResource, "schedule_for_deletion_days", "8"),
					// Key list data source
					resource.TestCheckResourceAttrPair(keyResource, "id", keysDataSource, "keys.0.id"),
					resource.TestCheckResourceAttr(keysDataSource, "matched", "1"),
					// Key version list data source
					resource.TestCheckResourceAttr(versionDataSource, "versions.#", "2"),
				),
			},
			{
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					// Key resource
					resource.TestCheckResourceAttr(keyResource, "version_summary.#", "2"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.algorithm", "RSA"),
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					// Key list data source
					resource.TestCheckResourceAttr(keysDataSource, "keys.#", "1"),
					resource.TestCheckResourceAttr(keysDataSource, "matched", "1"),
					// Key version list data source
					resource.TestCheckResourceAttr(versionDataSource, "versions.#", "2"),
					resource.TestCheckResourceAttr(versionDataSource, "matched", "2"),
					resource.TestCheckResourceAttrSet(versionDataSource, "versions.0.id"),
				),
			},
			// ModifyPlan: vault changed to a random UUID - expect plan-time error on key.
			{
				Config:      modifyKeyConfigStr,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
			// ModifyPlan: cckm_key_id changed to a random UUID - expect plan-time error on key version.
			{
				Config:      modifyVersionConfigStr,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
		},
	})
}

// scheduleOciKeyDeletionOutOfBand calls the OCI key schedule-deletion API directly,
// bypassing Terraform. Used in tests that verify provider behaviour when a key enters
// SCHEDULING_DELETION state without Terraform's knowledge.
// Failures are intentionally ignored - the test will catch any unexpected state.
func scheduleOciKeyDeletionOutOfBand(keyID string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	payload, _ := json.Marshal(map[string]int{"days": 7})
	_, _ = client.PostDataV2(
		context.Background(),
		"oob-schedule-oci-key-deletion-"+keyID,
		common.URL_OCI+"/keys/"+keyID+"/schedule-deletion",
		payload,
	)
}

// scheduleOciKeyVersionDeletionOutOfBand calls the OCI key version schedule-deletion API
// directly, bypassing Terraform.
// Failures are intentionally ignored - the test will catch any unexpected state.
func scheduleOciKeyVersionDeletionOutOfBand(keyID, versionID string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	payload, _ := json.Marshal(map[string]int{"days": 7})
	_, _ = client.PostDataV2(
		context.Background(),
		"oob-schedule-oci-version-deletion-"+versionID,
		common.URL_OCI+"/keys/"+keyID+"/versions/"+versionID+"/schedule-deletion",
		payload,
	)
}

// deleteOciVaultOOB removes a CipherTrust Manager OCI vault registration out-of-band
// (i.e. without going through Terraform). It is idempotent - if the vault is already
// gone it returns silently. Errors are logged as warnings; the function never fails
// the test on its own because the test steps that follow will surface any real problem.
func deleteOciVaultOOB(t *testing.T, vaultID string) {
	t.Helper()
	if vaultID == "" {
		t.Log("deleteOciVaultOOB: vaultID is empty, skipping")
		return
	}
	client, ok := createCMClient()
	if !ok {
		t.Log("deleteOciVaultOOB: could not create CM client, skipping OOB delete")
		return
	}
	ctx := context.Background()
	_, err := client.DeleteByURL(ctx, uuid.NewString(), common.URL_OCI+"/vaults/"+vaultID)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not found") {
			t.Logf("deleteOciVaultOOB: vault %s already absent", vaultID)
			return
		}
		t.Logf("deleteOciVaultOOB: warning - failed to delete vault %s: %s", vaultID, err.Error())
		return
	}
	t.Logf("deleteOciVaultOOB: deleted vault %s out-of-band", vaultID)
}

// TestCckmOCIKeyImmutabilityAndUpdate verifies that:
//   - Changing immutable attributes (algorithm, length) produces a plan-time error
//     and does NOT destroy and recreate the key.
//   - After a rejected plan, RefreshState confirms the OCI key is still ENABLED and unchanged.
//   - Valid updates (name, enable_key, freeform_tags) are applied correctly.
func TestCckmOCIKeyImmutabilityAndUpdate(t *testing.T) {
	connectionResource := initCckmOCITest(t)

	keyName := "tf-" + uuid.New().String()[:8]
	keyNameUpdated := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"

	// createConfig: the baseline key used throughout the test.
	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			enable_key = true
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, keyName)

	// badAlgorithmConfig: tries to change algorithm - immutable, should error at plan time.
	badAlgorithmConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			enable_key = true
			name = "%s"
			oci_key_params = {
				algorithm       = "AES"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, keyName)

	// badLengthConfig: tries to change length - immutable, should error at plan time.
	badLengthConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			enable_key = true
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 512
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, keyName)

	// updateConfig: valid update - new name, disable key, add freeform tag.
	updateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			enable_key = false
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				freeform_tags   = { env = "test" }
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, keyNameUpdated)

	// restoreConfig: re-enable the key, remove freeform tag.
	restoreConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			enable_key = true
			name = "%s"
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				freeform_tags   = {}
				length          = 256
				protection_mode = "SOFTWARE"
			}
			vault = ciphertrust_oci_vault.vault.id
		}`, keyNameUpdated)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create - verify key is ENABLED.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.algorithm", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.length", "256"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "SOFTWARE"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
				),
			},
			{
				// Step 2: attempting to change algorithm should fail at plan time - key must NOT be destroyed.
				Config:      badAlgorithmConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				// Step 3: re-apply valid config to confirm key is still ENABLED and algorithm unchanged.
				// (RefreshState cannot be used here because the previous PlanOnly step leaves the bad
				// config in the working directory, which would trigger ModifyPlan again.)
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.algorithm", "RSA"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
				),
			},
			{
				// Step 4: attempting to change length should fail at plan time - key must NOT be destroyed.
				Config:      badLengthConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
			{
				// Step 5: re-apply valid config to confirm key is still ENABLED and length unchanged.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.length", "256"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
				),
			},
			{
				// Step 6: valid update - disable key, update name, add freeform tag.
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "false"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "DISABLED"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.freeform_tags.env", "test"),
				),
			},
			{
				// Step 7: re-enable key and remove freeform tag.
				Config: restoreConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "enable_key", "true"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
				),
			},
		},
	})
}

// TestCckmOCIKeyScheduledForDeletionRefresh verifies that when an OCI key is scheduled
// for deletion out-of-band (without Terraform), a subsequent terraform refresh retains
// the resource in state and issues a warning rather than removing it from state.
func TestCckmOCIKeyScheduledForDeletionRefresh(t *testing.T) {
	connectionResource := initCckmOCITest(t)
	keyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"

	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name  = "%s"
			vault = ciphertrust_oci_vault.vault.id
		}`, keyName)

	var capturedKeyID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create a minimal OCI key; capture the CM ID for OOB deletion.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", keyResource)
						}
						capturedKeyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: schedule the key for deletion out-of-band, then refresh state.
				// Expected: provider issues a warning (not an error) and retains the resource
				// in state with lifecycle_state = "SCHEDULING_DELETION".
				PreConfig: func() {
					scheduleOciKeyDeletionOutOfBand(capturedKeyID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", keyResource)
						}
						if rs.Primary.ID != capturedKeyID {
							return fmt.Errorf("expected id %q, got %q", capturedKeyID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "SCHEDULING_DELETION"),
				),
			},
		},
	})
}

// TestCckmOCIKeyScheduledForDeletionUpdate verifies that when an OCI key is scheduled
// for deletion out-of-band, a subsequent terraform apply that includes a name update
// produces a "Provider produced inconsistent result" error. OCI auto-disables the key
// when scheduling deletion, causing the actual state (enable_key=false) to differ from
// the plan (enable_key=true from the schema default), which the Terraform framework
// detects as an inconsistent result. The resource remains in state after this failure.
func TestCckmOCIKeyScheduledForDeletionUpdate(t *testing.T) {
	connectionResource := initCckmOCITest(t)
	keyName := "tf-" + uuid.New().String()[:8]
	keyNameUpdated := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"

	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name  = "%s"
			vault = ciphertrust_oci_vault.vault.id
		}`, keyName)

	updateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name  = "%s"
			vault = ciphertrust_oci_vault.vault.id
		}`, keyNameUpdated)

	var capturedKeyID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create a minimal OCI key; capture the CM ID for OOB deletion.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", keyResource)
						}
						capturedKeyID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: schedule the key for deletion out-of-band, then apply a name update.
				// Expected: OCI auto-disables the key when scheduling deletion, causing the
				// actual enable_key state (false) to differ from the plan (true from the schema
				// default). The Terraform framework raises an inconsistent result error.
				PreConfig: func() {
					scheduleOciKeyDeletionOutOfBand(capturedKeyID)
				},
				Config:      updateConfig,
				ExpectError: regexp.MustCompile("Provider produced inconsistent result"),
			},
		},
	})
}

// TestCckmOCIKeyVersionScheduledForDeletionRefresh verifies that when an OCI native key
// version is scheduled for deletion out-of-band, a subsequent terraform refresh retains
// the resource in state and issues a warning rather than removing it from state.
// Two versions are created so that v1 is non-current and eligible for deletion scheduling.
func TestCckmOCIKeyVersionScheduledForDeletionRefresh(t *testing.T) {
	connectionResource := initCckmOCITest(t)
	keyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"
	v1Resource := "ciphertrust_oci_key_version.v1"
	v2Resource := "ciphertrust_oci_key_version.v2"

	// Create key + v1 + v2. v2 depends_on v1 so v1 is created first.
	// After both are created, v2 is the current version and v1 is non-current.
	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name  = "%s"
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}
		resource "ciphertrust_oci_key_version" "v2" {
			depends_on  = [ciphertrust_oci_key_version.v1]
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyName)

	var capturedKeyID, capturedV1ID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create key + two versions; capture parent key CM ID and v1 CM ID.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
					resource.TestCheckResourceAttrSet(v2Resource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", v1Resource)
						}
						capturedV1ID = rs.Primary.ID
						capturedKeyID = rs.Primary.Attributes["cckm_key_id"]
						return nil
					},
				),
			},
			{
				// Step 2: schedule v1 for deletion out-of-band, then refresh state.
				// Expected: v1 is retained in state with lifecycle_state = "SCHEDULING_DELETION".
				// v2 remains ENABLED.
				PreConfig: func() {
					scheduleOciKeyVersionDeletionOutOfBand(capturedKeyID, capturedV1ID)
				},
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", v1Resource)
						}
						if rs.Primary.ID != capturedV1ID {
							return fmt.Errorf("expected v1 id %q, got %q", capturedV1ID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(v1Resource, "oci_key_version_params.lifecycle_state", "SCHEDULING_DELETION"),
					resource.TestCheckResourceAttr(v2Resource, "oci_key_version_params.lifecycle_state", "ENABLED"),
				),
			},
		},
	})
}

func TestCckmOCIKeyVersionScheduledForDeletionUpdate(t *testing.T) {
	connectionResource := initCckmOCITest(t)
	keyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"
	v1Resource := "ciphertrust_oci_key_version.v1"

	createConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name  = "%s"
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id = ciphertrust_oci_key.key.id
		}
		resource "ciphertrust_oci_key_version" "v2" {
			depends_on  = [ciphertrust_oci_key_version.v1]
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyName)

	updateConfig := connectionResource + fmt.Sprintf(`
		resource "ciphertrust_oci_key" "key" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name  = "%s"
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "v1" {
			cckm_key_id                = ciphertrust_oci_key.key.id
			schedule_for_deletion_days = 10
		}
		resource "ciphertrust_oci_key_version" "v2" {
			depends_on  = [ciphertrust_oci_key_version.v1]
			cckm_key_id = ciphertrust_oci_key.key.id
		}`, keyName)

	var capturedKeyID, capturedV1ID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create key + two versions; capture parent key CM ID and v1 CM ID.
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttrSet(v1Resource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", v1Resource)
						}
						capturedV1ID = rs.Primary.ID
						capturedKeyID = rs.Primary.Attributes["cckm_key_id"]
						return nil
					},
				),
			},
			{
				// Step 2: schedule v1 for deletion out-of-band, then apply a schedule_for_deletion_days update.
				// Expected: Update detects SCHEDULING_DELETION, issues a warning (not an error),
				// and retains v1 in state.
				PreConfig: func() {
					scheduleOciKeyVersionDeletionOutOfBand(capturedKeyID, capturedV1ID)
				},
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[v1Resource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", v1Resource)
						}
						if rs.Primary.ID != capturedV1ID {
							return fmt.Errorf("expected v1 id %q, got %q", capturedV1ID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr(v1Resource, "oci_key_version_params.lifecycle_state", "SCHEDULING_DELETION"),
				),
			},
		},
	})
}

// TestCckmOCIKeyRestoreFromBackup verifies that setting restore_from_backup_trigger on a
// native OCI key triggers a restore from the most recent OCI backup.
// Applicable only to HSM-protected keys in OCI Virtual Private Vaults.
// Skipped if CCKM_OCI_VP_VAULT_OCID is not set.
func TestCckmOCIKeyRestoreFromBackup(t *testing.T) {
	vpVaultOCID := os.Getenv("CCKM_OCI_VP_VAULT_OCID")
	if vpVaultOCID == "" {
		t.Skip("CCKM_OCI_VP_VAULT_OCID not set")
	}

	connectionResource := initCckmOCITest(t)

	// List buckets accessible from the standard vault's compartment so the VP vault
	// can be configured with bucket storage, which is required for HSM key backup/restore.
	// Register the virtual private vault alongside the standard vault.
	vpVaultResource := fmt.Sprintf(`
		data "ciphertrust_get_oci_buckets" "buckets" {
			connection_id  = ciphertrust_oci_connection.oci_connection.id
			compartment_id = ciphertrust_oci_vault.vault.compartment_id
			limit          = 1
		}

		resource "ciphertrust_oci_vault" "vp_vault" {
			connection_id    = ciphertrust_oci_connection.oci_connection.id
			vault_id         = "%s"
			region           = local.region
			bucket_name      = data.ciphertrust_get_oci_buckets.buckets.buckets[0].name
			bucket_namespace = data.ciphertrust_get_oci_buckets.buckets.buckets[0].namespace
		}`, vpVaultOCID)

	baseConfig := connectionResource + vpVaultResource

	keyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"
	versionResource := "ciphertrust_oci_key_version.version"

	createConfig := fmt.Sprintf(`
			resource "ciphertrust_oci_key" "key" {
				name = "%s"
				oci_key_params = {
					algorithm       = "AES"
					compartment_id  = ciphertrust_oci_vault.vp_vault.compartment_id
					length          = 32
					protection_mode = "HSM"
				}
				vault = ciphertrust_oci_vault.vp_vault.id
			}
			resource "ciphertrust_oci_key_version" "version" {
				cckm_key_id = ciphertrust_oci_key.key.id
			}`, keyName)

	restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_oci_key" "key" {
				name = "%s"
				oci_key_params = {
					algorithm       = "AES"
					compartment_id  = ciphertrust_oci_vault.vp_vault.compartment_id
					length          = 32
					protection_mode = "HSM"
				}
				restore_from_backup_trigger = "1"
				vault = ciphertrust_oci_vault.vp_vault.id
			}
			resource "ciphertrust_oci_key_version" "version" {
				cckm_key_id = ciphertrust_oci_key.key.id
			}`, keyName)

	var capturedVersionUpdatedAt string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create an HSM-protected native key and a version on the VP vault.
				Config: baseConfig + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "HSM"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", versionResource)
						}
						capturedVersionUpdatedAt = rs.Primary.Attributes["updated_at"]
						return nil
					},
				),
			},
			{
				// Step 2: set restore_from_backup_trigger to trigger a restore from backup.
				// Verify the trigger attribute is reflected in state.
				Config: baseConfig + restoreConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "restore_from_backup_trigger", "1"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
				),
			},
			{
				// Step 3: refresh state to re-read version attributes from the API,
				// then verify updated_at changed after the restore.
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", versionResource)
						}
						newUpdatedAt := rs.Primary.Attributes["updated_at"]
						if capturedVersionUpdatedAt != "" && newUpdatedAt == capturedVersionUpdatedAt {
							return fmt.Errorf("expected version updated_at to change after restore, got same value: %s", newUpdatedAt)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestCckmOCIByokKeyRestoreFromBackup verifies that setting restore_from_backup_trigger on a
// native OCI key and on a BYOK OCI key triggers a restore from the most recent OCI backup.
// Applicable only to HSM-protected keys in OCI Virtual Private Vaults.
// Skipped if CCKM_OCI_VP_VAULT_OCID is not set.
func TestCckmOCIByokKeyRestoreFromBackup(t *testing.T) {
	vpVaultOCID := os.Getenv("CCKM_OCI_VP_VAULT_OCID")
	if vpVaultOCID == "" {
		t.Skip("CCKM_OCI_VP_VAULT_OCID not set")
	}

	connectionResource := initCckmOCITest(t)

	// List buckets accessible from the standard vault's compartment so the VP vault
	// can be configured with bucket storage, which is required for HSM key backup/restore.
	// Register the virtual private vault alongside the standard vault.
	vpVaultResource := fmt.Sprintf(`
		data "ciphertrust_get_oci_buckets" "buckets" {
			connection_id  = ciphertrust_oci_connection.oci_connection.id
			compartment_id = ciphertrust_oci_vault.vault.compartment_id
			limit          = 1
		}

		resource "ciphertrust_oci_vault" "vp_vault" {
			connection_id    = ciphertrust_oci_connection.oci_connection.id
			vault_id         = "%s"
			region           = local.region
			bucket_name      = data.ciphertrust_get_oci_buckets.buckets.buckets[0].name
			bucket_namespace = data.ciphertrust_get_oci_buckets.buckets.buckets[0].namespace
		}`, vpVaultOCID)

	baseConfig := connectionResource + vpVaultResource

	cmKeyName := "tf-" + uuid.New().String()[:8]
	cmVersionKeyName := "tf-" + uuid.New().String()[:8]
	ociKeyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_byok_key.key"
	versionResource := "ciphertrust_oci_byok_key_version.version"

	createConfig := fmt.Sprintf(`
			resource "ciphertrust_cm_key" "cm_key" {
				name       = "%s"
				algorithm  = "AES"
				usage_mask = local.cm_key_usage_mask
			}
			resource "ciphertrust_cm_key" "cm_version_key" {
				name       = "%s"
				algorithm  = "AES"
				usage_mask = local.cm_key_usage_mask
			}
			resource "ciphertrust_oci_byok_key" "key" {
				name = "%s"
				oci_key_params = {
					compartment_id  = ciphertrust_oci_vault.vp_vault.compartment_id
					protection_mode = "HSM"
				}
				source_key_id   = ciphertrust_cm_key.cm_key.id
				source_key_tier = "local"
				vault           = ciphertrust_oci_vault.vp_vault.id
			}
			resource "ciphertrust_oci_byok_key_version" "version" {
				cckm_key_id   = ciphertrust_oci_byok_key.key.id
				source_key_id = ciphertrust_cm_key.cm_version_key.id
			}`, cmKeyName, cmVersionKeyName, ociKeyName)

	restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_cm_key" "cm_key" {
				name       = "%s"
				algorithm  = "AES"
				usage_mask = local.cm_key_usage_mask
			}
			resource "ciphertrust_cm_key" "cm_version_key" {
				name       = "%s"
				algorithm  = "AES"
				usage_mask = local.cm_key_usage_mask
			}
			resource "ciphertrust_oci_byok_key" "key" {
				name = "%s"
				oci_key_params = {
					compartment_id  = ciphertrust_oci_vault.vp_vault.compartment_id
					protection_mode = "HSM"
				}
				restore_from_backup_trigger = "1"
				source_key_id   = ciphertrust_cm_key.cm_key.id
				source_key_tier = "local"
				vault           = ciphertrust_oci_vault.vp_vault.id
			}
			resource "ciphertrust_oci_byok_key_version" "version" {
				cckm_key_id   = ciphertrust_oci_byok_key.key.id
				source_key_id = ciphertrust_cm_key.cm_version_key.id
			}`, cmKeyName, cmVersionKeyName, ociKeyName)

	var capturedVersionUpdatedAt string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create an HSM-protected BYOK key and a BYOK version on the VP vault.
				Config: baseConfig + createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.protection_mode", "HSM"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.lifecycle_state", "ENABLED"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", versionResource)
						}
						capturedVersionUpdatedAt = rs.Primary.Attributes["updated_at"]
						return nil
					},
				),
			},
			{
				// Step 2: set restore_from_backup_trigger to trigger a restore from backup.
				// Verify the trigger attribute is reflected in state.
				Config: baseConfig + restoreConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "restore_from_backup_trigger", "1"),
					resource.TestCheckResourceAttrSet(versionResource, "id"),
				),
			},
			{
				// Step 3: refresh state to re-read version attributes from the API,
				// then verify updated_at changed after the restore.
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[versionResource]
						if !ok {
							return fmt.Errorf("resource not found in state: %s", versionResource)
						}
						newUpdatedAt := rs.Primary.Attributes["updated_at"]
						if capturedVersionUpdatedAt != "" && newUpdatedAt == capturedVersionUpdatedAt {
							return fmt.Errorf("expected version updated_at to change after restore, got same value: %s", newUpdatedAt)
						}
						return nil
					},
				),
			},
		},
	})
}
