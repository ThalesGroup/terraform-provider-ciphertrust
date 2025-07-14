package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func initCckmOCITest(t *testing.T) string {

	keyFile := os.Getenv("OCI_KEYFILE")
	pubKeyFP := os.Getenv("OCI_PUBKEY_FP")
	region := os.Getenv("OCI_REGION")
	tenancyOCID := os.Getenv("OCI_TENANCY_OCID")
	userOCID := os.Getenv("OCI_USER_OCID")
	compartmentOCID := os.Getenv("OCI_COMPARTMENT_DEV_OCID")
	vaultOCID := os.Getenv("OCI_VAULT_OCID")

	ok := keyFile != "" && pubKeyFP != "" && region != "" && tenancyOCID != "" && userOCID != "" && compartmentOCID != "" && vaultOCID != ""
	if !ok {
		t.Skip("Failed to get OCI connection environment variables")
	}
	name := "tf-" + uuid.New().String()[:8]
	config := `
		locals {
			compartment_ocid  = "%s"
			vault_ocid          = "%s"
			region              = "%s"
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
		compartmentOCID, vaultOCID, region,
		keyFile, name, pubKeyFP, region, tenancyOCID, userOCID)
	return resourceStr
}

func TestCckmOCIKeysAndVersionsBYOK(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	compartment2OCID := os.Getenv("OCI_COMPARTMENT_PROD_OCID")
	if compartment2OCID == "" {
		//t.Skip("Failed to get second compartment to test change of compartment")
	}

	localsConfig := `locals {
		connection_name     = "tf-%s"
		cm_key_name         = "tf-%s"
		oci_key_name        = "tf-%s"
		oci_min_key_name    = "tf-%s"
		cm_key_version_name = "tf-%s"
		rotation_job_name   = "tf-%s"
		rotation_job_name_2 = "tf-%s"
		oci_key_name_update = "tf-%s"
		compartment_2_ocid  = "%s"
	}`

	localsResource := fmt.Sprintf(localsConfig,
		uuid.New().String()[:8], uuid.New().String()[:8], uuid.New().String()[:8], uuid.New().String()[:8],
		uuid.New().String()[:8], uuid.New().String()[:8], uuid.New().String()[:8], uuid.New().String()[:8],
		compartment2OCID)

	maxConfig := `
		%s
		%s

		# Create a rotation scheduler
		resource "ciphertrust_scheduler" "scheduler_1" {
			end_date = "2027-03-07T14:24:00Z"
			cckm_key_rotation_params {
				cloud_name       = "oci"
			}
			name       = local.rotation_job_name
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}

		# Create an AES CipherTrust key
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = 60
		}

		# Create a byok OCI key
		resource "ciphertrust_oci_byok_key" "aes" {
			enable_key = true
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_1.id
				key_source    = "ciphertrust"
			}
			name            = local.oci_key_name
			oci_key_params = {
				compartment_id  = local.compartment_ocid
				protection_mode = "SOFTWARE"
				defined_tags = [
					{
						tag = "CCKM_OCI_1"
						values = {
							"TagKey1" = "TagValue1"
							"TagKey2" = "TagValue2"
						}
					},
					{
					tag = "CCKM_OCI"
						values = {
							"CCKM_OCI_Tag_1" = "cckmocitag1"
							"CCKM_OCI_Tag_2" = "cckmocitag2"
							"CCKM_OCI_Tag_3" = "cckmocitag3"
						}
					}
				]
				freeform_tags = {
					bonjour = "french"
					hello = "english"
				}
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}

		# Create an AES CipherTrust key for the key version
		resource "ciphertrust_cm_key" "cm_key_version" {
			name      = local.cm_key_version_name
			algorithm = "AES"
			usage_mask = 60
		}

		# Add a byok version to the key
		resource "ciphertrust_oci_byok_key_version" "byok_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add another byok version
		resource "ciphertrust_oci_byok_key_version" "byok_v2" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "native_v1" {
			# Make this version the current version
			depends_on = [ciphertrust_oci_byok_key_version.byok_v1, ciphertrust_oci_byok_key_version.byok_v2]
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
		}

		# List the key
		data "ciphertrust_oci_key_list" "keys" {
			depends_on = [ciphertrust_oci_key_version.native_v1]
			filters = {
				key_name = ciphertrust_oci_byok_key.aes.name
			}
		}

		# List the key's versions
		data "ciphertrust_oci_key_version_list" "versions" {
			key_id = ciphertrust_oci_byok_key.aes.id
			depends_on = [ciphertrust_oci_key_version.native_v1]
		}`

	updateConfig := `
		%s
		%s

		# Create a rotation scheduler
		resource "ciphertrust_scheduler" "scheduler_1" {
			end_date = "2027-03-07T14:24:00Z"
			cckm_key_rotation_params {
				cloud_name       = "oci"
			}
			name       = local.rotation_job_name
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}

		resource "ciphertrust_scheduler" "scheduler_2" {
			end_date = "2027-03-07T14:24:00Z"
			cckm_key_rotation_params {
			cloud_name       = "oci"
			}
			name       = local.rotation_job_name_2
			operation  = "cckm_key_rotation"
			run_at     = "0 9 * * sat"
			run_on     = "any"
			start_date = "2026-03-07T14:24:00Z"
		}

		# Create an AES CipherTrust key
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = 60
		}

		# Create a byok OCI key
		resource "ciphertrust_oci_byok_key" "aes" {
			enable_key = true
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.scheduler_2.id
				key_source    = "ciphertrust"
			}
			name            = local.oci_key_name_update
			oci_key_params = {
				#compartment_id  = local.compartment_2_ocid
				compartment_id  = local.compartment_ocid
				protection_mode = "SOFTWARE"
				defined_tags = [
					{
						tag = "CCKM_OCI_1"
						values = {
							"TagKey3" = "TagValue3"
						}
					},
					{
						tag = "CCKM_OCI"
						values = {
							"CCKM_OCI_Tag_3" = "cckmocitag3"
							"CCKM_OCI_Tag_4" = "cckmocitag4"
						}
					}
				]
				freeform_tags = {
					bonjour = "french"
					ciao = "italian"
				}
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}

		# Create an AES CipherTrust key for the key version
		resource "ciphertrust_cm_key" "cm_key_version" {
			name      = local.cm_key_version_name
			algorithm = "AES"
			usage_mask = 60
		}

		# Add a byok version to the key
		resource "ciphertrust_oci_byok_key_version" "byok_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add another byok version
		resource "ciphertrust_oci_byok_key_version" "byok_v2" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "native_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
		}`

	minConfig := `
		%s
		%s

		# Create an AES CipherTrust key
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name         = local.cm_key_name
			algorithm    = "AES"
			usage_mask   = 60
		}

		# Create a byok OCI key
		resource "ciphertrust_oci_byok_key" "aes" {
			name            = local.oci_key_name
			oci_key_params = {
				protection_mode = "SOFTWARE"
				compartment_id  = local.compartment_ocid
			}
			source_key_id   = ciphertrust_cm_key.cm_aes_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}

		# Create an AES CipherTrust key for the key version
		resource "ciphertrust_cm_key" "cm_key_version" {
			name      = local.cm_key_version_name
			algorithm = "AES"
			usage_mask = 60
		}

		# Add a byok version to the key
		resource "ciphertrust_oci_byok_key_version" "byok_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add another byok version
		resource "ciphertrust_oci_byok_key_version" "byok_v2" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
			source_key_id = ciphertrust_cm_key.cm_key_version.id
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "native_v1" {
			cckm_key_id = ciphertrust_oci_byok_key.aes.id
		}`

	keyResource := "ciphertrust_oci_byok_key.aes"
	keysDataSource := "data.ciphertrust_oci_key_list.keys"
	versionDataSource := "data.ciphertrust_oci_key_version_list.versions"

	createResourceStr := fmt.Sprintf(maxConfig, localsResource, connectionResource)
	updateResourceStr := fmt.Sprintf(updateConfig, localsResource, connectionResource)
	minResourceStr := fmt.Sprintf(minConfig, localsResource, connectionResource)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "labels.%", "2"),
					resource.TestCheckResourceAttr(keysDataSource, "keys.#", "1"),
					resource.TestCheckResourceAttr(versionDataSource, "versions.#", "4"),
				),
			},
			{
				Config: updateResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "version_summary.#", "4"),
				),
			},
			{
				// Get the key deleted
				Config: connectionResource,
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: minResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "labels.%", "0"),
				),
			},
			{
				Config: updateResourceStr,
				Check:  resource.ComposeTestCheckFunc(),
			},
			{
				Config: createResourceStr,
				Check:  resource.ComposeTestCheckFunc(),
			},
		},
	})
}
