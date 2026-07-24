// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCTELDTGroupCommSvcClientsDataSource(t *testing.T) {
	groupName := "tf-ldt-group-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_ldtgroupcomms" "ldt_group" {
			name        = "%s"
			description = "LDT Group for data source test"
		}

		data "ciphertrust_cte_ldtcommgroup_clients_list" "ds" {
			group_name = ciphertrust_cte_ldtgroupcomms.ldt_group.name
			depends_on = [ciphertrust_cte_ldtgroupcomms.ldt_group]
		}
	`, groupName)

	resourceName := "ciphertrust_cte_ldtgroupcomms.ldt_group"
	datasourceName := "data.ciphertrust_cte_ldtcommgroup_clients_list.ds"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					// Field-level value on the data source itself: the queried
					// group name round-trips. A freshly created LDT comm group has
					// no member clients yet, so the clients list is legitimately
					// empty (asserts the data source returns a valid empty result).
					resource.TestCheckResourceAttr(datasourceName, "group_name", groupName),
					resource.TestCheckResourceAttr(datasourceName, "clients.#", "0"),
				),
			},
		},
	})
}
