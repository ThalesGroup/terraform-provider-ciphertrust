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

# A policy to attach the key rule to
resource "ciphertrust_cte_policy" "std_policy" {
  name        = "std_policy"
  policy_type = "Standard"
  description = "Created via TF"
  never_deny  = true
  security_rules = [{
    effect        = "permit,audit"
    action        = "all_ops"
    partial_match = false
  }]
}

# Add a key rule to the policy
resource "ciphertrust_cte_policy_key_rule" "key_rule" {
  policy_id = ciphertrust_cte_policy.std_policy.id
  rule = {
    key_id = "test_key"
  }
}
