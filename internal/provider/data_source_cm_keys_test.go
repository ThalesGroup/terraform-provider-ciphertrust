// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccCMKeysListFilterConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name      = %q
  algorithm = "AES"
}

data "ciphertrust_cm_keys_list" "filtered" {
  filters    = { name = %q }
  depends_on = [ciphertrust_cm_key.test]
}
`, name, name)
}

func Test_CM_DataSourceCMKeysList_FiltersAttribute(t *testing.T) {
	RequireCM(t)
	name := "tfin419k-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMKeysListFilterConfig(name),
				Check: checkStep(t, "filters attribute accepted and applied",
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_keys_list.filtered", "keys.#", "1"),
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_keys_list.filtered", "keys.0.name", name),
				),
			},
		},
	})
}
