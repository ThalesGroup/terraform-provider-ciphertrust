package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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
	t.Skip("skipped")

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
