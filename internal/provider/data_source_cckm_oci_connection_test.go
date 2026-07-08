package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_CM_CckmOCIDataSourceConnection(t *testing.T) {
	ociKeyFile := os.Getenv("CCKM_OCI_KEY_FILE")
	ociPubKeyFP := os.Getenv("CCKM_OCI_FINGERPRINT")
	ociRegion := os.Getenv("CCKM_OCI_REGION")
	ociTenancyOCID := os.Getenv("CCKM_OCI_CONN_TENANCY")
	ociUserOCID := os.Getenv("CCKM_OCI_USER")
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
		data "ciphertrust_get_oci_regions" "regions_by_connection_name" {
			connection_id = ciphertrust_oci_connection.connection.name
		}
		data "ciphertrust_get_oci_regions" "regions_by_connection_id" {
			connection_id = ciphertrust_oci_connection.connection.id
		}
		data "ciphertrust_get_oci_compartments" "compartments_no_limit" {
			connection_id = ciphertrust_oci_connection.connection.name
		}
		data "ciphertrust_get_oci_compartments" "compartments_with_limit" {
			connection_id = ciphertrust_oci_connection.connection.id
			limit = 1
		}
		data "ciphertrust_get_oci_vaults" "vaults_no_limit" {
			connection_id = ciphertrust_oci_connection.connection.name
			compartment_id = tolist(data.ciphertrust_get_oci_compartments.compartments_with_limit.compartments)[0].id
			region = data.ciphertrust_get_oci_regions.regions_by_connection_id.oci_regions.0
		}
		data "ciphertrust_get_oci_vaults" "vaults_with_limit" {
			limit = 1
			connection_id = ciphertrust_oci_connection.connection.name
			compartment_id = tolist(data.ciphertrust_get_oci_compartments.compartments_with_limit.compartments)[0].id
			region = data.ciphertrust_get_oci_regions.regions_by_connection_id.oci_regions.0
		}`

	name := "tf-" + uuid.New().String()[:8]
	connectionConfigStr := fmt.Sprintf(connectionConfig, ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	regionsByName := "data.ciphertrust_get_oci_regions.regions_by_connection_name"
	regionsById := "data.ciphertrust_get_oci_regions.regions_by_connection_id"
	compartmentsNoLimit := "data.ciphertrust_get_oci_compartments.compartments_no_limit"
	compartmentsWithLimit := "data.ciphertrust_get_oci_compartments.compartments_with_limit"
	vaultsNoLimit := "data.ciphertrust_get_oci_vaults.vaults_no_limit"
	vaultsWithLimit := "data.ciphertrust_get_oci_vaults.vaults_with_limit"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: connectionConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_oci_connection.connection", "id"),
					testCheckAttributeContains(regionsByName, "oci_regions.#", []string{"0"}, false),
					testCheckAttributeContains(regionsById, "oci_regions.#", []string{"0"}, false),
					testCheckAttributeContains(compartmentsNoLimit, "compartments.#", []string{"0"}, false),
					testCheckAttributeContains(compartmentsNoLimit, "compartments.#", []string{"2"}, false),
					testCheckAttributeContains(compartmentsWithLimit, "compartments.#", []string{"0"}, false),
					testCheckAttributeContains(compartmentsWithLimit, "compartments.#", []string{"1"}, true),
					resource.TestCheckResourceAttrSet(compartmentsWithLimit, "compartments.0.id"),
					testCheckAttributeContains(vaultsNoLimit, "vaults.#", []string{"0"}, false),
					testCheckAttributeContains(vaultsNoLimit, "vaults.#", []string{"2"}, false),
					testCheckAttributeContains(vaultsWithLimit, "vaults.#", []string{"0"}, false),
					testCheckAttributeContains(vaultsWithLimit, "vaults.#", []string{"1"}, true),
				),
			},
		},
	})
}
