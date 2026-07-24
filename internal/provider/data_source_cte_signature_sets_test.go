package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCTESignatureSetsDataSource(t *testing.T) {
	signatureSetName := "tf-sigset-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_signature_set" "test_sigset" {
			name        = "%s"
			description = "Created for CTE signature sets data source test"
			type        = "Application"
			source_list = ["/tmp"]
		}

		data "ciphertrust_cte_signature_sets" "ds" {
			depends_on = [ciphertrust_cte_signature_set.test_sigset]
		}
	`, signatureSetName)

	datasourceName := "data.ciphertrust_cte_signature_sets.ds"
	resourceName := "ciphertrust_cte_signature_set.test_sigset"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(datasourceName, "signature_sets.0.id"),
					resource.TestCheckResourceAttrSet(datasourceName, "signature_sets.0.name"),
				),
			},
		},
	})
}
