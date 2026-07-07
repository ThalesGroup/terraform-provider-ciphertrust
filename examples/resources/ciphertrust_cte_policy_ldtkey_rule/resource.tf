terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
  address  = "https://10.10.10.10"
  username = "admin"
  password = "ChangeMe101!"
}

# An LDT policy to attach the LDT key rule to
resource "ciphertrust_cte_policy" "ldt_policy" {
  name        = "LDT_policy"
  policy_type = "LDT"
  description = "Temp policy for testing...."
  never_deny  = true

  ldt_key_rules = [{
    current_key = {
      key_id   = "clear_key"
      key_type = ""
    }
    transformation_key = {
      key_id   = "ldt_key"
      key_type = ""
    }
  }]

  security_rules = [{
    effect        = "permit"
    action        = "all_ops"
    partial_match = false
  }]
}

# Add an LDT key rule to the policy
resource "ciphertrust_cte_policy_ldtkey_rule" "ldt_key_rule" {
  policy_id = ciphertrust_cte_policy.ldt_policy.id
  rule = {
    is_exclusion_rule = false
    resource_set_id   = "cm-test"
    current_key = {
      key_id = "clear_key"
    }
    transformation_key = {
      key_id = "ldt_key2"
    }
  }
}
