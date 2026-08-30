package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCTEClientsDataSource(t *testing.T) {
	clientName := "tf-client-" + uuid.New().String()[:8]

	cteClientConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_client" "cte_client" {
			name                     = "%s"
			password_creation_method = "GENERATE"
			description              = "Created for CTE clients data source test"
		}

		data "ciphertrust_cte_clients_list" "cte_clients" {
			depends_on = [ciphertrust_cte_client.cte_client]
			filters = {
				name = ciphertrust_cte_client.cte_client.name
			}
		}
	`, clientName)

	// badFilterConfig: data source with an unrecognized filter key.
	// The provider rejects it at plan time (TFIN-620).
	badFilterConfig := cteClientConfig + `
		data "ciphertrust_cte_clients_list" "bad_filter" {
			filters = { totally_bogus_filter_key = "x" }
		}`

	// zeroMatchConfig: data source with a valid filter key and a value that
	// cannot match any client. Verifies that zero results are returned as an
	// empty list (clients.# = 0) rather than null (TFIN-620).
	zeroMatchConfig := cteClientConfig + `
		data "ciphertrust_cte_clients_list" "zero_match" {
			filters = { name = "definitely-does-not-exist-xyz" }
		}`

	datasourceName := "data.ciphertrust_cte_clients_list.cte_clients"
	resourceName := "ciphertrust_cte_client.cte_client"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cteClientConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(datasourceName, "clients.#", "1"),
					resource.TestCheckResourceAttrPair(datasourceName, "clients.0.id", resourceName, "id"),
					resource.TestCheckResourceAttr(datasourceName, "clients.0.name", clientName),
					resource.TestCheckResourceAttr(datasourceName, "clients.0.description", "Created for CTE clients data source test"),
				),
			},
			{
				// Step 2: bogus filter key - provider rejects it at plan time.
				Config:      providerConfig + badFilterConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("not a supported filter key"),
			},
			{
				// Step 3: valid filter with a value that cannot match any client.
				// Checks that zero results are returned as an empty list, not null.
				Config: providerConfig + zeroMatchConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_cte_clients_list.zero_match", "clients.#", "0"),
				),
			},
		},
	})
}
