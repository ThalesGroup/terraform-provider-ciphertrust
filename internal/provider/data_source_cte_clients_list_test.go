package provider

import (
	"fmt"
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
		},
	})
}
