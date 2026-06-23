package provider

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/tidwall/gjson"
)

// cleanupCckmOCIVaults lists all CCKM OCI vault registrations in CipherTrust Manager and deletes each one.
// This is called via PreCheck on every CCKM OCI test to remove any vault resources left behind by a
// previous failed test run. Only runs when TF_CCKM_CLEANUP=true is set, so that contributors do not
// accidentally wipe their own CM resources. All errors are logged as warnings - the cleanup is
// best-effort and never fails the test.
func cleanupCckmOCIVaults() {
	if os.Getenv("TF_CCKM_CLEANUP") != "true" {
		return
	}
	client, ok := createCMClient()
	if !ok {
		fmt.Println("cleanupCckmOCIVaults: could not create CM client, skipping cleanup")
		return
	}
	ctx := context.Background()
	filters := url.Values{}
	filters.Add("limit", "1000")
	response, err := client.ListWithFilters(ctx, uuid.NewString(), common.URL_OCI+"/vaults/", filters)
	if err != nil {
		fmt.Printf("** cleanupCckmOCIVaults: failed to list vaults: %s\n", err.Error())
		return
	}
	resources := gjson.Get(response, "resources").Array()
	if len(resources) == 0 {
		return
	}
	for _, r := range resources {
		vaultID := gjson.Get(r.Raw, "id").String()
		vaultName := gjson.Get(r.Raw, "name").String()
		_, err := client.DeleteByURL(ctx, uuid.NewString(), common.URL_OCI+"/vaults/"+vaultID)
		if err != nil {
			fmt.Printf("** cleanupCckmOCIVaults: failed to delete vault '%s' (%s): %s\n", vaultName, vaultID, err.Error())
		} else {
			fmt.Printf("cleanupCckmOCIVaults: deleted vault '%s'\n", vaultName)
		}
	}
}

// TestCckmOCIMinimalConfig verifies that a resource configuration containing only
// the minimal required attributes is accepted and applied without error for every
// OCI CCKM resource type: native key + key version, BYOK key + BYOK key version,
// and vault ACL. A RefreshState step confirms there is no post-apply plan drift.
func TestCckmOCIMinimalConfig(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	keyConfig := `
		resource "ciphertrust_oci_key" "native_key" {
			oci_key_params = {
				algorithm       = "RSA"
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				length          = 256
				protection_mode = "SOFTWARE"
			}
			name  = "%s"
			vault = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_key_version" "native_version" {
			cckm_key_id = ciphertrust_oci_key.native_key.id
		}
		resource "ciphertrust_cm_key" "cm_key" {
			name       = "%s"
			algorithm  = "AES"
			usage_mask = local.cm_key_usage_mask
		}
		resource "ciphertrust_oci_byok_key" "byok_key" {
			name = "%s"
			oci_key_params = {
				compartment_id  = ciphertrust_oci_vault.vault.compartment_id
				protection_mode = "SOFTWARE"
			}
			source_key_id   = ciphertrust_cm_key.cm_key.id
			source_key_tier = "local"
			vault           = ciphertrust_oci_vault.vault.id
		}
		resource "ciphertrust_oci_byok_key_version" "byok_version" {
			cckm_key_id   = ciphertrust_oci_byok_key.byok_key.id
			source_key_id = ciphertrust_cm_key.cm_key.id
		}
		resource "ciphertrust_groups" "acl_group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_groups.acl_group.id
			actions  = ["view"]
		}`

	fullConfig := connectionResource + fmt.Sprintf(keyConfig,
		"tf-"+uuid.New().String()[:8],
		"tf-"+uuid.New().String()[:8],
		"tf-"+uuid.New().String()[:8],
		"tf-"+uuid.New().String()[:8],
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fullConfig,
			},
			{
				RefreshState: true,
			},
		},
	})
}

func TestCckmOCIVault(t *testing.T) {

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
			connection_id = ciphertrust_oci_connection.connection.name
		}
		data "ciphertrust_get_oci_compartments" "compartments" {
			connection_id = ciphertrust_oci_connection.connection.id
			limit = 1
		}
		data "ciphertrust_get_oci_vaults" "vaults" {
			limit = 1
			connection_id = ciphertrust_oci_connection.connection.name
			compartment_id = tolist(data.ciphertrust_get_oci_compartments.compartments.compartments)[0].id
			region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		}
		 resource "ciphertrust_oci_vault" "vault" {
		   region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		   connection_id = ciphertrust_oci_connection.connection.name
		   vault_id = tolist(data.ciphertrust_get_oci_vaults.vaults.vaults)[0].vault_id
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
			compartment_id = tolist(data.ciphertrust_get_oci_compartments.compartments.compartments)[0].id
			region = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		}
		resource "ciphertrust_oci_vault" "vault" {
				region = %s
				connection_id = ciphertrust_oci_connection.connection_two.name
				vault_id = tolist(data.ciphertrust_get_oci_vaults.vaults.vaults)[0].vault_id
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
	updateConfigStr := fmt.Sprintf(updateConfig,
		ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID,
		"data.ciphertrust_get_oci_regions.regions.oci_regions.0",
		ociKeyFile, nameTwo, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	modifyVaultConfigStr := fmt.Sprintf(updateConfig,
		ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID,
		`"fake-oci-region"`,
		ociKeyFile, nameTwo, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	connectionResource := "ciphertrust_oci_connection.connection"
	connectionTwoResource := "ciphertrust_oci_connection.connection_two"
	vaultResource := "ciphertrust_oci_vault.vault"
	vaultsDataSource := "data.ciphertrust_get_oci_vaults.vaults"
	compartmentsDataSource := "data.ciphertrust_get_oci_compartments.compartments"
	regionsDataSource := "data.ciphertrust_get_oci_regions.regions"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: connectionConfigStr,
				Check: resource.ComposeTestCheckFunc(
					// Regions data source
					resource.TestCheckResourceAttrSet(regionsDataSource, "oci_regions.0"),
					// Compartments data source
					resource.TestCheckResourceAttrSet(compartmentsDataSource, "compartments.0.id"),
					// Vaults data source
					resource.TestCheckResourceAttrSet(vaultsDataSource, "vaults.0.vault_id"),
					resource.TestCheckResourceAttrSet(vaultsDataSource, "vaults.0.lifecycle_state"),
					// Vault resource
					resource.TestCheckResourceAttrSet(vaultResource, "id"),
					resource.TestCheckResourceAttrPair(vaultResource, "connection_id", connectionResource, "name"),
					resource.TestCheckResourceAttrPair(vaultResource, "vault_id", vaultsDataSource, "vaults.0.vault_id"),
					resource.TestCheckResourceAttrPair(vaultResource, "compartment_id", compartmentsDataSource, "compartments.0.id"),
					resource.TestCheckResourceAttrPair(vaultResource, "region", regionsDataSource, "oci_regions.0"),
				),
			},
			{
				RefreshState: true,
			},
			{
				ResourceName:            vaultResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"connection_id"},
			},
			{
				Config: updateConfigStr,
				Check: resource.ComposeTestCheckFunc(
					// Regions data source
					resource.TestCheckResourceAttrSet(regionsDataSource, "oci_regions.0"),
					// Compartments data source
					resource.TestCheckResourceAttrSet(compartmentsDataSource, "compartments.0.id"),
					// Vaults data source
					resource.TestCheckResourceAttrSet(vaultsDataSource, "vaults.0.vault_id"),
					resource.TestCheckResourceAttrSet(vaultsDataSource, "vaults.0.lifecycle_state"),
					// Vault resource
					resource.TestCheckResourceAttrSet(vaultResource, "id"),
					resource.TestCheckResourceAttrPair(vaultResource, "connection_id", connectionTwoResource, "name"),
					resource.TestCheckResourceAttrPair(vaultResource, "vault_id", vaultsDataSource, "vaults.0.vault_id"),
					resource.TestCheckResourceAttrPair(vaultResource, "compartment_id", compartmentsDataSource, "compartments.0.id"),
				),
			},
			{
				RefreshState: true,
			},
			// ModifyPlan: region changed to a fake value - expect plan-time error (region is immutable).
			{
				Config:      modifyVaultConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Immutable attribute change detected"),
			},
			{
				ResourceName:            vaultResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"connection_id"},
			},
		},
	})
}
