package provider

import (
	"context"
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

// TestCckmOCIKeyVaultDeletedOOB verifies provider behaviour when the CipherTrust Manager
// OCI vault registration is removed out-of-band while a ciphertrust_oci_key resource is
// still tracked in Terraform state. Two scenarios are exercised in a single destroy step:
//
//  1. Vault delete - vault registration already gone OOB; delete adds a warning and removes
//     the vault cleanly from state (no error).
//
//  2. Key delete   - vault is gone but the key CM record still exists; the key destroy
//     schedules it for deletion normally and removes it from state (no error).
func TestCckmOCIKeyVaultDeletedOOB(t *testing.T) {
	connectionResource := initCckmOCITest(t)

	keyName := "tf-" + uuid.New().String()[:8]
	keyResource := "ciphertrust_oci_key.key"

	// createConfig: connection + vault + key.
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

	// destroyConfig: removes both vault and key resources so Terraform destroys them.
	// The vault will already be gone OOB (warning expected); the key destroy runs normally.
	destroyConfig := connectionResource

	// capturedVaultID is populated during Step 1 so the PreConfig in Step 2 can delete
	// the vault registration out-of-band before Terraform's destroy runs.
	var capturedVaultID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create the key; capture the vault CM ID for the OOB delete.
			{
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(keyResource, "id"),
					resource.TestCheckResourceAttr(keyResource, "oci_key_params.algorithm", "RSA"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[keyResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", keyResource)
						}
						capturedVaultID = rs.Primary.Attributes["vault"]
						t.Logf("captured vault ID %s", capturedVaultID)
						return nil
					},
				),
			},
			// Step 2: delete vault OOB then apply destroyConfig (no key, no vault in config).
			// Terraform destroys both resources:
			//   - Vault: already gone (404) -> getOciVault warns, Terraform removes from state.
			//   - Key:   still in CM -> deleteOCIKey schedules it for deletion normally.
			// Expected: no error, only warnings.
			{
				PreConfig: func() {
					deleteOciVaultOOB(t, capturedVaultID)
				},
				Config: destroyConfig,
			},
		},
	})
}

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
			name            = local.oci_key_name
			vault           = %s
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "version" {
			cckm_key_id = %s
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
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
					resource.TestCheckResourceAttrPair(versionResource, "cckm_key_id", keyResource, "id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.vault_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.key_id"),
					resource.TestCheckResourceAttrSet(versionResource, "oci_key_version_params.version_id"),
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
					// Version resource
					resource.TestCheckResourceAttrSet(versionResource, "id"),
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
