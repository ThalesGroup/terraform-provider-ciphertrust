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

resource "ciphertrust_cte_policy" "standard_policy" {
  name        = "TF_CTE_Policy_CG"
  policy_type = "Standard"
  description = "Created via TF"
  never_deny  = true

  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_client_group" "cte_client_group" {
  name         = "TF_CTE_ClientGroup"
  cluster_type = "NON-CLUSTER"
  description  = "Created via TF"
}


resource "ciphertrust_cte_clientgroup_guardpoint" "dir_auto_gp_cg" {
  client_group_id = ciphertrust_cte_client_group.cte_client_group.id
  guard_points = {
    "/test/gp_cg1" = {
      guard_point_params = {
       guard_point_type = "directory_manual"
        policy_id        = ciphertrust_cte_policy.standard_policy.id
        #mfa_enabled = true
        #guard_enabled = false
      }
    }
  }
}

# These fields are ignored during intitial apply but can be updated, their default values are set (mfa_enabled=false, guard_enabled-true)
  #mfa_enabled = true
  #guard_enabled = false