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

# A policy to attach the security rule to
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

# Add a security rule to the policy
resource "ciphertrust_cte_policy_security_rule" "security_rule" {
  policy_id = ciphertrust_cte_policy.std_policy.id
  rule = {
    effect               = "deny,audit"
    partial_match        = false
    exclude_resource_set = true
    exclude_user_set     = true
    resource_set_id      = "test-resource-set"
    user_set_id          = "test-user-set"
  }
}
