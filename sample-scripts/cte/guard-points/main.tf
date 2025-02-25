terraform {
	required_providers {
	  ciphertrust = {
		source = "thalesgroup.com/oss/ciphertrust"
		version = "1.0.0"
	  }
	}
}

provider "ciphertrust" {
    address = "https://192.168.2.158"
    username = "admin"
    password = "ChangeIt01!"
    bootstrap = "no"
    alias = "primary"
}

resource "ciphertrust_cte_policy" "standard_policy" {
    provider        = ciphertrust.primary
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
    provider                    = ciphertrust.primary
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
  provider = ciphertrust.primary
  guard_paths = ["/opt/path1"]
  client_id = ciphertrust_cte_client.cte_client.id
  guard_point_params = {
    guard_point_type = "directory_auto"
    guard_enabled = true
    policy_id = ciphertrust_cte_policy.standard_policy.name
  }
}