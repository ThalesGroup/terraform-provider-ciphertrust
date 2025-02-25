terraform {
	required_providers {
	  ciphertrust = {
		source  = "thalesgroup.com/oss/ciphertrust"
		version = "1.0.0"
	  }
	}
}

provider "ciphertrust" {
    address   = "https://192.168.2.158"
    username  = "admin"
    password  = "ChangeIt01!"
    bootstrap = "no"
    alias     = "primary"
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