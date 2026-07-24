// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCTEPolicyDataTxRulesDataSource(t *testing.T) {
	policyName := "tf-policy-dtx-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cte_policy" "test_policy" {
			name        = "%s"
			description = "Created for CTE policy data tx rules data source test"
			policy_type = "Standard"
			security_rules = [
				{
					action = "key_op"
					effect = "permit,applykey"
				}
			]
			key_rules = [
				{
					key_id = "clear_key"
				}
			]
		}

		resource "ciphertrust_cte_policy_data_tx_rule" "test_rule" {
			policy_id = ciphertrust_cte_policy.test_policy.id
			rule = {
				key_id = "clear_key"
			}
		}

		data "ciphertrust_cte_policy_data_tx_rules" "ds" {
			depends_on = [ciphertrust_cte_policy_data_tx_rule.test_rule]
			policy     = ciphertrust_cte_policy.test_policy.id
		}
	`, policyName)

	datasourceName := "data.ciphertrust_cte_policy_data_tx_rules.ds"
	ruleResourceName := "ciphertrust_cte_policy_data_tx_rule.test_rule"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(ruleResourceName, "rule.id"),

					resource.TestCheckResourceAttr(datasourceName, "rules.#", "1"),
					resource.TestCheckResourceAttrPair(datasourceName, "rules.0.id", ruleResourceName, "rule.id"),
					resource.TestCheckResourceAttr(datasourceName, "rules.0.key_id", "clear_key"),
					resource.TestCheckResourceAttrPair(datasourceName, "rules.0.policy_id", "ciphertrust_cte_policy.test_policy", "id"),
				),
			},
		},
	})
}
