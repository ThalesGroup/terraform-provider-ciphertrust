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

# A policy to attach the signature rule to
resource "ciphertrust_cte_policy" "csi_policy" {
  name        = "csi_policy"
  policy_type = "CSI"
  never_deny  = true
  key_rules = [{
    key_id = "clear_key"
  }]
  security_rules = [{ effect = "deny" }]
  description    = "Temp CSI policy for testing purpose."
}

# Add a signature rule to the policy
resource "ciphertrust_cte_policy_signature_rule" "sig_rule" {
  policy_id             = ciphertrust_cte_policy.csi_policy.id
  signature_set_id_list = ["signset-containerimge-8646731"]
}
