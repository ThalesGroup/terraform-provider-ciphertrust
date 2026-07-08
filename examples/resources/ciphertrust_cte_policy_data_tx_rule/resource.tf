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

# A policy to attach the data transformation rule to
resource "ciphertrust_cte_policy" "dxt_policy" {
  name        = "DxForm_Policy"
  policy_type = "Standard"
  description = "policy for testing using terraform..."
  never_deny  = true
  key_rules   = [{ key_id = "clear_key" }]

  data_transform_rules = [{
    key_id = "clear_key"
  }]

  security_rules = [{
    effect = "permit"
    action = "key_op"
  }]
}

# Add a data transformation rule to the policy
resource "ciphertrust_cte_policy_data_tx_rule" "dxt_key_rule" {
  policy_id = ciphertrust_cte_policy.dxt_policy.id
  rule = {
    key_id          = "test_key"
    resource_set_id = "cm-test"
  }
}
