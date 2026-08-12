package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCckmOCIDataSourceCompartmentList verifies the ciphertrust_oci_compartments_list
// data source. It uses initCckmOCITest to create an OCI connection and register a
// vault (which causes CM to sync compartments), then:
//   - rejects an unrecognized filter key at plan time
//   - returns an empty list (not null) for a valid filter that matches nothing
//   - lists all compartments without filters
//   - filters by name, id, tenancy, and compartment_id using values from the unfiltered list
//
// All infra cases must return at least one compartment.
func TestCckmOCIDataSourceCompartmentList(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	invalidFilterConfig := `
		data "ciphertrust_oci_compartments_list" "bad_filter" {
			filters = {
				totally_bogus_filter = "x"
			}
		}`

	zeroMatchConfig := `
		data "ciphertrust_oci_compartments_list" "zero_match" {
			filters = {
				name = "definitely-does-not-exist-xyz"
			}
		}`

	config := `
		%s

		# List all compartments synced into CipherTrust Manager.
		data "ciphertrust_oci_compartments_list" "all" {
			depends_on = [ciphertrust_oci_vault.vault]
		}

		# Filter by the name of the first compartment in the unfiltered list.
		data "ciphertrust_oci_compartments_list" "by_name" {
			filters = {
				name = tolist(data.ciphertrust_oci_compartments_list.all.compartments)[0].name
			}
			depends_on = [data.ciphertrust_oci_compartments_list.all]
		}

		# Filter by the CM resource id of the first compartment.
		data "ciphertrust_oci_compartments_list" "by_id" {
			filters = {
				id = tolist(data.ciphertrust_oci_compartments_list.all.compartments)[0].id
			}
			depends_on = [data.ciphertrust_oci_compartments_list.all]
		}

		# Filter by the tenancy of the first compartment.
		data "ciphertrust_oci_compartments_list" "by_tenancy" {
			filters = {
				tenancy = tolist(data.ciphertrust_oci_compartments_list.all.compartments)[0].tenancy
			}
			depends_on = [data.ciphertrust_oci_compartments_list.all]
		}

		# Filter by compartment_id (the parent compartment OCID) of the first compartment.
		data "ciphertrust_oci_compartments_list" "by_compartment_id" {
			filters = {
				compartment_id = tolist(data.ciphertrust_oci_compartments_list.all.compartments)[0].compartment_id
			}
			depends_on = [data.ciphertrust_oci_compartments_list.all]
		}
	`

	configStr := fmt.Sprintf(config, connectionResource)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: unrecognized filter key must be rejected at plan time.
				Config:      invalidFilterConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Unrecognized filter key`),
			},
			{
				// Step 2: valid filter with no matching compartment must return empty list, not null.
				Config: zeroMatchConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_oci_compartments_list.zero_match", "compartments.#", "0"),
					resource.TestCheckResourceAttr("data.ciphertrust_oci_compartments_list.zero_match", "matched", "0"),
				),
			},
			{
				// Step 3: full infra + data source checks.
				Config: configStr,
				Check: resource.ComposeTestCheckFunc(
					// Unfiltered list has at least one compartment.
					resource.TestCheckResourceAttrSet("data.ciphertrust_oci_compartments_list.all", "compartments.0.id"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_oci_compartments_list.all", "compartments.0.name"),

					// by_name returns at least one result.
					resource.TestCheckResourceAttrSet("data.ciphertrust_oci_compartments_list.by_name", "compartments.0.id"),

					// by_id returns at least one result and the id matches.
					resource.TestCheckResourceAttrSet("data.ciphertrust_oci_compartments_list.by_id", "compartments.0.id"),
					resource.TestCheckResourceAttrPair(
						"data.ciphertrust_oci_compartments_list.by_id", "compartments.0.id",
						"data.ciphertrust_oci_compartments_list.all", "compartments.0.id",
					),

					// by_tenancy returns at least one result.
					resource.TestCheckResourceAttrSet("data.ciphertrust_oci_compartments_list.by_tenancy", "compartments.0.id"),

					// by_compartment_id returns at least one result.
					resource.TestCheckResourceAttrSet("data.ciphertrust_oci_compartments_list.by_compartment_id", "compartments.0.id"),
				),
			},
		},
	})
}
