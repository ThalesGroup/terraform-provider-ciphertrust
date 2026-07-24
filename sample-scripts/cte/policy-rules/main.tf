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


 # Add Standard policy
resource "ciphertrust_cte_policy" "std_policy" {
    name            = "std_policy"
    policy_type     = "Standard"
    description     = "Created via TF"
    never_deny      = true
    security_rules  = [{
        effect               = "permit,audit"
        action               = "all_ops"
        partial_match        = false
    }]
}


# Add IDT policy 
resource "ciphertrust_cte_policy" "idt_policy" {
  name        = "IDT_policy"
  policy_type = "IDT"
  description = "Temp std policy for testing"

  idt_key_rules = [{
    current_key             = "clear_key"
    current_key_type        = ""
    transformation_key      = "idt_key"
    transformation_key_type = ""
}]

  security_rules = [{
    effect               = "permit"
    action               = "all_ops"
  }]

}

# Add Ldt policy rule
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
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    }
  ]

}

# Add Dxt policy rule
resource "ciphertrust_cte_policy" "dxt_policy" {
  name        = "DxForm_Policy"
  policy_type = "Standard"
  description = " policy for testing using terrafrom..."
  never_deny  = true
  key_rules = [{key_id = "clear_key"}]

  data_transform_rules = [{
    key_id = "clear_key"
  }]

  security_rules = [{
    effect               = "permit"
    action               = "key_op"
    }
  ]
}

# Add COS policy
resource "ciphertrust_cte_policy" "cos_policy" {
  name = "cos_policy"
  policy_type = "Cloud_Object_Storage"
  never_deny  = true

  key_rules = [{
    key_id = "cos_key"
  }]


  metadata = {
    restrict_update = false
  }

 security_rules = [ {effect = "deny"} ] 
  description = "Temp COS policy for testing purpose."
}

# Add CSI policy
resource "ciphertrust_cte_policy" "csi_policy" {
  name = "csi_policy"
  policy_type = "CSI"
  never_deny  = true 

  key_rules = [{
    key_id = "clear_key"
  }]

  metadata = {
    restrict_update = false
  }

  security_rules = [ {effect = "deny"} ] 
  signature_rules = [{signature_set_id = "signset-containerimge-36446638"}]
  description = "Temp CSI policy for testing purpose."
}


# Add Signature rule
resource "ciphertrust_cte_policy_signature_rule" "sig_rule" {
  policy_id             = ciphertrust_cte_policy.csi_policy.id
  signature_set_id_list = ["signset-containerimge-8646731"]
}


# Add Security rule
resource "ciphertrust_cte_policy_security_rule" "security_rule" {
  policy_id = ciphertrust_cte_policy.std_policy.id
  rule = {
    effect = "deny,audit"
    partial_match        = false
    exclude_resource_set = true
    exclude_user_set = true
    resource_set_id = "test-resource-set"
    user_set_id = "test-user-set"
  }
}


# Add key rule
resource "ciphertrust_cte_policy_key_rule" "key_rule" {
  policy_id = ciphertrust_cte_policy.std_policy.id
  rule = { 
     key_id = "test_key"
 }
}


# Add LDT key rule
resource "ciphertrust_cte_policy_ldtkey_rule" "ldt_key_rule" {
  policy_id = ciphertrust_cte_policy.ldt_policy.id

  rule = {
      is_exclusion_rule = false
      resource_set_id    = "cm-test"
      current_key = {
        key_id = "clear_key"
      },
      transformation_key = {
        key_id = "ldt_key2"
      }
    }
}

# Add datax key rule
resource "ciphertrust_cte_policy_data_tx_rule" "dxt_key_rule" {
  policy_id = ciphertrust_cte_policy.dxt_policy.id

  rule =  {
    key_id = "test_key"
    resource_set_id = "cm-test"
      }
}
