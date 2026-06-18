package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEClientGroup(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create
			{
				Config: providerConfig + `
resource "ciphertrust_cte_client_group" "cg" {
  name         = "testClientGroup1"
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_client_group.cg",
						"id",
					),
				),
			},

			// Step 2: Update basic fields
			{
				Config: providerConfig + `
			resource "ciphertrust_cte_client_group" "cg" {
			  name         = "testClientGroup1"
			  cluster_type = "NON-CLUSTER"
			  description  = "Updated via TF"

			  op_type               = "update"
			  communication_enabled = true
			  client_locked         = true
			}
			`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_client_group.cg",
						"id",
					),
				),
			},

			// Step 3: Add clients
			{
				Config: providerConfig + `
resource "ciphertrust_cte_client" "c1" {
  name                     = "client1"
  password_creation_method = "GENERATE"
  registration_allowed     = true
    communication_enabled = true
  client_locked = true
}

resource "ciphertrust_cte_client" "c2" {
  name                     = "client2"
  password_creation_method = "GENERATE"
  registration_allowed     = true
    communication_enabled = true
  client_locked = true
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = "testClientGroup1"
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
`,
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
				Config: providerConfig + `
resource "ciphertrust_cte_client" "c1" {
  name                     = "client1"
  password_creation_method = "GENERATE"
  registration_allowed     = true
    communication_enabled = true
  client_locked = true
}

resource "ciphertrust_cte_client" "c2" {
  name                     = "client2"
  password_creation_method = "GENERATE"
  registration_allowed     = true
    communication_enabled = true
  client_locked = true
}

resource "ciphertrust_cte_client_group" "cg" {
  name         = "testClientGroup1"
  cluster_type = "NON-CLUSTER"
  description  = "Updated via TF"
  communication_enabled = true
  client_locked = true

  op_type     = "remove-client"
  client_list = []
}
`,
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
