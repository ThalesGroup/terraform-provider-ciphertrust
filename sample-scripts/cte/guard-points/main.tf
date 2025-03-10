terraform {
  required_providers {
    ciphertrust = {
      source = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {
	address = "https://10.10.10.10"
	username = "admin"
	password = "ChangeMe101!"
}

resource "ciphertrust_cte_policy" "standard_policy" {
    name            = "TF_CTE_Policy"
    policy_type     = "Standard"
    description     = "Created via TF"
    never_deny      = true
    security_rules  = [{
        effect               = "permit,audit"
        action               = "all_ops"
        partial_match        = false
        exclude_resource_set = true
    }]
}

resource "ciphertrust_cte_client" "cte_client" {
    name                        = "TF_CTE_Client"
    client_type                 = "FS"
    registration_allowed        = true
    communication_enabled       = true
    description                 = "Created via TF"
    password_creation_method    = "GENERATE"
    labels                      = {
      color = "blue"
    }
}

resource "ciphertrust_cte_guardpoint" "dir_auto_gp" {
  guard_paths = ["/opt/path1"]
  client_id = ciphertrust_cte_client.cte_client.id
  guard_point_params = {
    guard_point_type = "directory_auto"
    guard_enabled = true
    policy_id = ciphertrust_cte_policy.standard_policy.name
  }
}