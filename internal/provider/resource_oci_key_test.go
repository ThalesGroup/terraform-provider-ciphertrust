package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmOCIKeysAndVersionsNative(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	localsConfig := `locals {
		connection_name     = "tf-%s"
		oci_key_name        = "tf-%s"
	}`

	localsResource := fmt.Sprintf(localsConfig, uuid.New().String()[:8], uuid.New().String()[:8])

	createConfig := `
		%s
		%s

		# Create a native OCI key
		resource "ciphertrust_oci_key" "rsa" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = local.compartment_ocid
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name            = local.oci_key_name
			vault           = ciphertrust_oci_vault.vault.id
		}

		# Add a native version to the key
		resource "ciphertrust_oci_key_version" "version" {
			cckm_key_id = ciphertrust_oci_key.rsa.id
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

	keyResource := "ciphertrust_oci_key.rsa"
	keysDataSource := "data.ciphertrust_oci_key_list.keys"
	versionDataSource := "data.ciphertrust_oci_key_version_list.versions"

	createResourceStr := fmt.Sprintf(createConfig, localsResource, connectionResource)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keysDataSource, "keys.#", "1"),
					resource.TestCheckResourceAttr(versionDataSource, "versions.#", "2"),
				),
			},
			{
				Config: createResourceStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(keyResource, "version_summary.#", "2"),
				),
			},
		},
	})
}
