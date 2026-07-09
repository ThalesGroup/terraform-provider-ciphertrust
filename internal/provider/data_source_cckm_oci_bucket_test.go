package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCckmOCIGetBuckets verifies the ciphertrust_get_oci_buckets data source.
// It uses initCckmOCITest to create an OCI connection and register a vault,
// then lists all compartments to obtain a compartment OCID, and finally
// fetches buckets for that compartment. At least one bucket must be returned.
func TestCckmOCIGetBuckets(t *testing.T) {

	connectionResource := initCckmOCITest(t)

	config := `
		%s

		# List all compartments synced into CipherTrust Manager.
		data "ciphertrust_oci_compartments_list" "all" {
			depends_on = [ciphertrust_oci_vault.vault]
		}

		# Fetch buckets for the first compartment in the list.
		data "ciphertrust_get_oci_buckets" "test" {
			connection_id  = ciphertrust_oci_connection.oci_connection.id
			compartment_id = tolist(data.ciphertrust_oci_compartments_list.all.compartments)[0].compartment_id
			depends_on     = [data.ciphertrust_oci_compartments_list.all]
		}
	`

	configStr := fmt.Sprintf(config, connectionResource)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: configStr,
				Check: resource.ComposeTestCheckFunc(
					// At least one bucket is returned.
					resource.TestCheckResourceAttrSet("data.ciphertrust_get_oci_buckets.test", "buckets.0.name"),
				),
			},
		},
	})
}
