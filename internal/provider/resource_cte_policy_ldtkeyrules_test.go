package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicyLDTKeyRule(t *testing.T) {
	RequireCM(t)

	suffix := uuid.New().String()[:8]
	key1Name := "ldt-key-initial-" + suffix
	key2Name := "ldt-key-new-" + suffix
	policyName := "LDT_policy-" + suffix
	rsName := "rs2-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{

			// Step 1: Create LDT Policy
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "key1" {
  name         = %q
  algorithm    = "aes"
  key_size     = 256
  usage_mask   = 76
  undeletable  = false
  unexportable = false
  xts          = false

  meta = {
    permissions = {
      decrypt_with_key = ["CTE Clients"]
      encrypt_with_key = ["CTE Clients"]
      export_key       = ["CTE Clients"]
      read_key         = ["CTE Clients"]
    }
    cte = {
      persistent_on_client = true
      encryption_mode      = "CBC"
      cte_versioned        = true
    }
  }
}

resource "ciphertrust_cte_policy" "ldt_policy" {
  name        = %q
  policy_type = "LDT"
  never_deny  = true

  ldt_key_rules = [{
    current_key = {
      key_id   = "clear_key"
      key_type = ""
    }

    transformation_key = {
      key_id   = ciphertrust_cm_key.key1.name
      key_type = ""
    }
  }]

  security_rules = [{
    effect        = "permit"
    action        = "all_ops"
    partial_match = false
  }]
}
`, key1Name, policyName),
			},

			// Step 2: Add new LDT key rule (ONLY transformation key changes)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "key1" {
  name         = %q
  algorithm    = "aes"
  key_size     = 256
  usage_mask   = 76
  undeletable  = false
  unexportable = false
  xts          = false

  meta = {
    permissions = {
      decrypt_with_key = ["CTE Clients"]
      encrypt_with_key = ["CTE Clients"]
      export_key       = ["CTE Clients"]
      read_key         = ["CTE Clients"]
    }
    cte = {
      persistent_on_client = true
      encryption_mode      = "CBC"
      cte_versioned        = true
    }
  }
}

resource "ciphertrust_cm_key" "key2" {
  name         = %q
  algorithm    = "aes"
  key_size     = 256
  usage_mask   = 76
  undeletable  = false
  unexportable = false
  xts          = false

  meta = {
    permissions = {
      decrypt_with_key = ["CTE Clients"]
      encrypt_with_key = ["CTE Clients"]
      export_key       = ["CTE Clients"]
      read_key         = ["CTE Clients"]
    }
    cte = {
      persistent_on_client = true
      encryption_mode      = "CBC"
      cte_versioned        = true
    }
  }
}

resource "ciphertrust_cte_resource_set" "rs2" {
  name = %q
}

resource "ciphertrust_cte_policy" "ldt_policy" {
  name        = %q
  policy_type = "LDT"
  never_deny  = true

  ldt_key_rules = [{
    current_key = {
      key_id   = "clear_key"
      key_type = ""
    }

    transformation_key = {
      key_id   = ciphertrust_cm_key.key1.name
      key_type = ""
    }
  }]

  security_rules = [{
    effect        = "permit"
    action        = "all_ops"
    partial_match = false
  }]
}

resource "ciphertrust_cte_policy_ldtkey_rule" "ldt_rule" {
  policy_id = ciphertrust_cte_policy.ldt_policy.id


  rule = {
    is_exclusion_rule = false

    resource_set_id = ciphertrust_cte_resource_set.rs2.name

    current_key = {
      key_id   = "clear_key"
      key_type = ""
    }

    transformation_key = {
      key_id   = ciphertrust_cm_key.key2.name
      key_type = ""
    }
  }
}
`, key1Name, key2Name, rsName, policyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy_ldtkey_rule.ldt_rule", "rule.id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
