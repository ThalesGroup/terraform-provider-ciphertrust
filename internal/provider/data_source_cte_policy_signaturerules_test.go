// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestCTEPolicySignatureRulesDataSource creates a CSI policy with a
// signature rule (signature rules are only valid on CSI policies, attached via a
// Container-Image signature set) and then reads it back through the
// ciphertrust_cte_policy_signature_rules data source, asserting the rule list is
// non-empty and carries the expected field-level values.
func TestCTEPolicySignatureRulesDataSource(t *testing.T) {
	suffix := uuid.New().String()[:8]
	policyName := "tf-sigrule-ds-" + suffix
	sigSetName := "tf-sigrule-ds-set-" + suffix
	const dsName = "data.ciphertrust_cte_policy_signature_rules.ds"

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_signature_set" "sigset" {
  name        = %q
  type        = "Container-Image"
  source_list = ["/usr/bin"]
}

resource "ciphertrust_cte_policy" "policy" {
  name        = %q
  policy_type = "CSI"
  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_policy_signature_rule" "sigrule" {
  policy_id             = ciphertrust_cte_policy.policy.id
  signature_set_id_list = [ciphertrust_cte_signature_set.sigset.name]
}

data "ciphertrust_cte_policy_signature_rules" "ds" {
  policy     = ciphertrust_cte_policy.policy.id
  depends_on = [ciphertrust_cte_policy_signature_rule.sigrule]
}
`, sigSetName, policyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dsName, "rules.#", "1"),
					resource.TestCheckResourceAttrSet(dsName, "rules.0.id"),
					resource.TestCheckResourceAttrPair(dsName, "rules.0.policy_id", "ciphertrust_cte_policy.policy", "id"),
					resource.TestCheckResourceAttrSet(dsName, "rules.0.signature_set_name"),
				),
			},
		},
	})
}
