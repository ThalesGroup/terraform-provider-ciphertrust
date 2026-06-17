package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEClientGroup(t *testing.T) {
	suffix := uuid.New().String()[:8]
	groupName := "testClientGroup1-" + suffix
	client1Name := "client1-" + suffix
	client2Name := "client2-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`, groupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_client_group.cg",
						"id",
					),
				),
			},

			// Step 2: Update basic fields
			{
				Config: providerConfig + fmt.Sprintf(`
			resource "ciphertrust_cte_client_group" "cg" {
			  name         = %q
			  cluster_type = "NON-CLUSTER"
			  description  = "Updated via TF"

			  op_type               = "update"
			  communication_enabled = true
			  client_locked         = true
			}
			`, groupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_client_group.cg",
						"id",
					),
				),
			},

			// Step 3: Add clients
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "c1" {
  name                     = %q
  password_creation_method = "GENERATE"
  registration_allowed     = true
    communication_enabled = true
  client_locked = true
}

resource "ciphertrust_cte_client" "c2" {
  name                     = %q
  password_creation_method = "GENERATE"
  registration_allowed     = true
    communication_enabled = true
  client_locked = true
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Updated via TF"
  communication_enabled = true
  client_locked = true

  op_type = "add-client"

  client_list = [
    ciphertrust_cte_client.c1.name,
    ciphertrust_cte_client.c2.name
  ]

  inherit_attributes = true
}
`, client1Name, client2Name, groupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_client_group.cg",
						"id",
					),

					// IMPORTANT CHECK
					resource.TestCheckResourceAttr(
						"ciphertrust_cte_client_group.cg",
						"client_list.#",
						"2",
					),
				),
			},

			// Step 4: Remove clients
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "c1" {
  name                     = %q
  password_creation_method = "GENERATE"
  registration_allowed     = true
    communication_enabled = true
  client_locked = true
}

resource "ciphertrust_cte_client" "c2" {
  name                     = %q
  password_creation_method = "GENERATE"
  registration_allowed     = true
    communication_enabled = true
  client_locked = true
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Updated via TF"
  communication_enabled = true
  client_locked = true

  op_type     = "remove-client"
  client_list = []
}
`, client1Name, client2Name, groupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_client_group.cg",
						"id",
					),

					// verify state is empty after removal
					resource.TestCheckResourceAttr(
						"ciphertrust_cte_client_group.cg",
						"client_list.#",
						"0",
					),
				),
			},
		},
	})
}
