// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCTEClientGuardPointDataSource(t *testing.T) {
	clientName := "tf-client-" + uuid.New().String()[:8]
	policyName := "tf-policy-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_policy" "policy" {
			name        = "%s"
			policy_type = "Standard"
			security_rules = [
				{
					action = "all_ops"
					effect = "permit,audit"
				}
			]
		}

		resource "ciphertrust_cte_client" "client" {
			name                     = "%s"
			password_creation_method = "GENERATE"
		}

		resource "ciphertrust_cte_client_guardpoint" "gp" {
			client_id = ciphertrust_cte_client.client.id

			guard_points = {
				"/tmp/tf-test-gp" = {
					guard_point_params = {
						guard_point_type = "directory_auto"
						policy_id        = ciphertrust_cte_policy.policy.id
					}
				}
			}
		}

		data "ciphertrust_cte_client_guardpoint" "ds" {
			depends_on  = [ciphertrust_cte_client_guardpoint.gp]
			client_name = ciphertrust_cte_client.client.name
		}
	`, policyName, clientName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ciphertrust_cte_client_guardpoint.ds", "client_guardpoint.0.id"),
					resource.TestCheckResourceAttr("data.ciphertrust_cte_client_guardpoint.ds", "client_guardpoint.0.client_name", clientName),
					resource.TestCheckResourceAttr("data.ciphertrust_cte_client_guardpoint.ds", "client_guardpoint.0.guard_path", "/tmp/tf-test-gp"),
					resource.TestCheckResourceAttr("data.ciphertrust_cte_client_guardpoint.ds", "client_guardpoint.0.guard_point_type", "directory_auto"),
					resource.TestCheckResourceAttrPair(
						"data.ciphertrust_cte_client_guardpoint.ds", "client_guardpoint.0.policy_id",
						"ciphertrust_cte_policy.policy", "id",
					),
					// Verify the map entry ID was populated after creation
					resource.TestCheckResourceAttrSet(
						"ciphertrust_cte_client_guardpoint.gp",
						"guard_points./tmp/tf-test-gp.id",
					),
				),
			},
		},
	})
}
