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

// TestCTESignatureSetsDataSourceLimit covers TFIN-584: the data source now
// exposes "limit"/"skip" attributes so callers can bound the result set
// instead of always retrieving every signature set on CM. This creates two
// signature sets and verifies limit = 1 returns exactly one result.
func TestCTESignatureSetsDataSourceLimit(t *testing.T) {
	nameA := "tf-sigset-" + uuid.New().String()[:8]
	nameB := "tf-sigset-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_signature_set" "test_sigset_a" {
			name = "%s"
			type = "Application"
		}

		resource "ciphertrust_cte_signature_set" "test_sigset_b" {
			name = "%s"
			type = "Application"
		}

		data "ciphertrust_cte_signature_sets" "ds_limited" {
			depends_on = [
				ciphertrust_cte_signature_set.test_sigset_a,
				ciphertrust_cte_signature_set.test_sigset_b,
			]
			limit = 1
		}
	`, nameA, nameB)

	datasourceName := "data.ciphertrust_cte_signature_sets.ds_limited"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, "limit", "1"),
					resource.TestCheckResourceAttr(datasourceName, "signature_sets.#", "1"),
				),
			},
		},
	})
}
