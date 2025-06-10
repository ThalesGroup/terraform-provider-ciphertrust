package provider

import (
	"fmt"
	"github.com/google/uuid"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmOCIVault(t *testing.T) {

	ociKeyFile := os.Getenv("OCI_KEYFILE")
	ociPubKeyFP := os.Getenv("OCI_PUBKEY_FP")
	ociRegion := os.Getenv("OCI_REGION")
	ociTenancyOCID := os.Getenv("OCI_TENANCY_OCID")
	ociUserOCID := os.Getenv("OCI_USER_OCID")
	ok := ociKeyFile != "" && ociPubKeyFP != "" && ociRegion != "" && ociTenancyOCID != "" && ociUserOCID != ""
	if !ok {
		t.Skip("Failed to set OCI connection variables")
	}

	connectionConfig := `
		resource "ciphertrust_oci_connection" "connection" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}
		data "ciphertrust_get_oci_regions" "regions" {
			connection_id = ciphertrust_oci_connection.connection.name
		}
		data "ciphertrust_get_oci_compartments" "compartments" {
			connection_id = ciphertrust_oci_connection.connection.id
			limit = 1
		}
		data "ciphertrust_get_oci_vaults" "vaults" {
			limit = 1
			connection_id = ciphertrust_oci_connection.connection.name
			compartment_id = data.ciphertrust_get_oci_compartments.compartments.compartments.0.id
			region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		}
		 resource "ciphertrust_oci_vault" "vault" {
		   region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		   connection_id = ciphertrust_oci_connection.connection.name
		   vault_id = data.ciphertrust_get_oci_vaults.vaults.vaults.0.vault_id
		}`

	updateConfig := `
		resource "ciphertrust_oci_connection" "connection" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}
		data "ciphertrust_get_oci_regions" "regions" {
			connection_id = ciphertrust_oci_connection.connection.name
		}
		data "ciphertrust_get_oci_compartments" "compartments" {
			connection_id = ciphertrust_oci_connection.connection.id
			limit = 1
		}
		data "ciphertrust_get_oci_vaults" "vaults" {
			limit = 1
			connection_id = ciphertrust_oci_connection.connection.name
			compartment_id = data.ciphertrust_get_oci_compartments.compartments.compartments.0.id
			region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		}
		resource "ciphertrust_oci_vault" "vault" {
				region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
				connection_id = ciphertrust_oci_connection.connection_two.name
				vault_id = data.ciphertrust_get_oci_vaults.vaults.vaults.0.vault_id
		}
		resource "ciphertrust_oci_connection" "connection_two" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}`

	name := "tf-" + uuid.New().String()[:8]
	nameTwo := "tf-" + uuid.New().String()[:8]
	connectionConfigStr := fmt.Sprintf(connectionConfig, ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	updateConfigStr := fmt.Sprintf(updateConfig, ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID,
		ociKeyFile, nameTwo, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	connectionTwoResource := "ciphertrust_oci_connection.connection_two"
	vaultResource := "ciphertrust_oci_vault.vault"
	vaultsDataSource := "data.ciphertrust_get_oci_vaults.vaults"
	compartmentsDataSource := "data.ciphertrust_get_oci_compartments.compartments"
	regionsDataSource := "data.ciphertrust_get_oci_regions.regions"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: connectionConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(vaultResource, "vault_id", vaultsDataSource, "vaults.0.vault_id"),
					resource.TestCheckResourceAttrPair(vaultResource, "compartment_id", compartmentsDataSource, "compartments.0.id"),
					resource.TestCheckResourceAttrPair(vaultResource, "region", regionsDataSource, "oci_regions.0"),
				),
			},
			{
				Config: updateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(vaultResource, "connection_id", connectionTwoResource, "name"),
					resource.TestCheckResourceAttrPair(vaultResource, "vault_id", vaultsDataSource, "vaults.0.vault_id"),
					resource.TestCheckResourceAttrPair(vaultResource, "compartment_id", compartmentsDataSource, "compartments.0.id"),
				),
			},
		},
	})
}
