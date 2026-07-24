// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCckmOCIDataSourceCompartmentList verifies the ciphertrust_oci_compartments_list
// data source. It uses initCckmOCITest to create an OCI connection and register a
// vault (which causes CM to sync compartments), then:
//   - lists all compartments without filters
//   - filters by name, id, tenancy, and compartment_id using values from the unfiltered list
//
// All cases must return at least one compartment.
func TestCckmOCIDataSourceCompartmentList(t *testing.T) {

	connectionResource := initCckmOCITest(t)

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
