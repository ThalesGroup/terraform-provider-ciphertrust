package provider

import (
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmOCIDataSourceVault(t *testing.T) {

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
		data "ciphertrust_get_oci_regions" "regions" {
			connection_id = ciphertrust_oci_connection.connection.id
		}
		data "ciphertrust_get_oci_compartments" "compartments" {
			connection_id = ciphertrust_oci_connection.connection.id
		}
		data "ciphertrust_get_oci_vaults" "vaults" {
			connection_id = ciphertrust_oci_connection.connection.id
			compartment_id = tolist(data.ciphertrust_get_oci_compartments.compartments.compartments)[0].id
			region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		}
		resource "ciphertrust_oci_vault" "vault" {
			region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
			connection_id = ciphertrust_oci_connection.connection.id
			vault_id = tolist(data.ciphertrust_get_oci_vaults.vaults.vaults)[0].vault_id
		}
		data "ciphertrust_oci_vault_list" "by_name" {
			filters = {
				display_name = ciphertrust_oci_vault.vault.name
			}
		}
		data "ciphertrust_oci_vault_list" "no_filters" {
			depends_on = [ciphertrust_oci_vault.vault]
		}`

	name := "tf-" + uuid.New().String()[:8]
	connectionConfigStr := fmt.Sprintf(connectionConfig, ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	vaultByName := "data.ciphertrust_oci_vault_list.by_name"
	vaultsNoFilters := "data.ciphertrust_oci_vault_list.no_filters"
	vaultsDataSource := "data.ciphertrust_get_oci_vaults.vaults"
	compartmentsDataSource := "data.ciphertrust_get_oci_compartments.compartments"

	invalidFilterConfig := `
		data "ciphertrust_oci_vault_list" "bad_filter" {
			filters = {
				totally_bogus_filter = "x"
			}
		}`

	zeroMatchConfig := `
		data "ciphertrust_oci_vault_list" "zero_match" {
			filters = {
				display_name = "definitely-does-not-exist-xyz"
			}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Unrecognized filter key must be rejected at plan time.
				Config:      invalidFilterConfig,
				ExpectError: regexp.MustCompile(`Unrecognized filter key`),
			},
			{
				// Step 2: valid filter with no matching vault must return empty list, not null.
				Config: zeroMatchConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_oci_vault_list.zero_match", "vaults.#", "0"),
					resource.TestCheckResourceAttr("data.ciphertrust_oci_vault_list.zero_match", "matched", "0"),
				),
			},
			{
				// Step 3: infrastructure + data source checks.
				Config: connectionConfigStr,
				Check: resource.ComposeTestCheckFunc(
					// Vault resource
					resource.TestCheckResourceAttrSet("ciphertrust_oci_vault.vault", "id"),
					// By-name vault list data source
					resource.TestCheckResourceAttr(vaultByName, "vaults.#", "1"),
					resource.TestCheckResourceAttrSet(vaultByName, "vaults.0.name"),
					resource.TestCheckResourceAttrPair(vaultByName, "vaults.0.vault_id", vaultsDataSource, "vaults.0.vault_id"),
					resource.TestCheckResourceAttrPair(vaultByName, "vaults.0.compartment_id", compartmentsDataSource, "compartments.0.id"),
					// No-filter vault list: fragile count omitted; check at least one entry present
					resource.TestCheckResourceAttrSet(vaultsNoFilters, "vaults.0.vault_id"),
				),
			},
		},
	})
}

func TestCckmOCIDataSourceGetVaultsCreateValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// empty connection_id must be rejected at plan time
				Config: `
					data "ciphertrust_get_oci_vaults" "test" {
						connection_id  = ""
						compartment_id = "ocid1.compartment.fake"
						region         = "us-ashburn-1"
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			{
				// whitespace-only connection_id must be rejected at plan time
				Config: `
					data "ciphertrust_get_oci_vaults" "test" {
						connection_id  = "   "
						compartment_id = "ocid1.compartment.fake"
						region         = "us-ashburn-1"
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			{
				// empty compartment_id must be rejected at plan time
				Config: `
					data "ciphertrust_get_oci_vaults" "test" {
						connection_id  = "my-connection"
						compartment_id = ""
						region         = "us-ashburn-1"
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			{
				// whitespace-only compartment_id must be rejected at plan time
				Config: `
					data "ciphertrust_get_oci_vaults" "test" {
						connection_id  = "my-connection"
						compartment_id = "   "
						region         = "us-ashburn-1"
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			{
				// empty region must be rejected at plan time
				Config: `
					data "ciphertrust_get_oci_vaults" "test" {
						connection_id  = "my-connection"
						compartment_id = "ocid1.compartment.fake"
						region         = ""
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			{
				// whitespace-only region must be rejected at plan time
				Config: `
					data "ciphertrust_get_oci_vaults" "test" {
						connection_id  = "my-connection"
						compartment_id = "ocid1.compartment.fake"
						region         = "   "
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
		},
	})
}
