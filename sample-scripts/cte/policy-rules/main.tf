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

# Add standard policy rule
resource "ciphertrust_cte_policy" "std_policy" {
  name        = "std_Policy"
  policy_type = "Standard"
  description = "Temp std policy for testing."
  never_deny  = false
  key_rules = [{
    key_id = "clear_key"
  }]
  metadata = {
    restrict_update = false
  }
  security_rules = [{
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    exclude_resource_set = true
  }]
}

# Add IDT policy rule
resource "ciphertrust_cte_policy" "idt_policy" {
  name        = "idt_Policy"
  policy_type = "IDT"
  description = "Temp std policy for testing."
  never_deny  = false
  idt_key_rules = [{
    current_key             = "clear_key"
    current_key_type        = ""
    transformation_key      = "idt_key"
    transformation_key_type = ""
  }]
  security_rules = [{
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    exclude_resource_set = true
  }]
}
# Add Ldt policy rule
resource "ciphertrust_cte_policy" "ldt_policy" {
  name        = "LDT_policy"
  policy_type = "LDT"
  description = "Temp policy for testing."
  never_deny  = false
  ldt_key_rules = [{
    current_key = {
      key_id   = "clear_key"
      key_type = ""
    }


    transformation_key = {
      key_id   = "aes256_cs1_key"
      key_type = ""
    }
  }]
  security_rules = [{
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    exclude_resource_set = true
    }
  ]
}

# Add Dxt policy rule
resource "ciphertrust_cte_policy" "dxt_policy" {
  name        = "DxForm_Policy"
  policy_type = "Standard"
  description = " policy for testing using terrafrom."
  never_deny  = true
  key_rules = [{
    key_id = "idt_key"
  }]

  data_transform_rules = [{
    key_id = "clear_key"


  }]


  security_rules = [{
    effect               = "permit"
    action               = "key_op"
    partial_match        = false
    exclude_resource_set = true
    exclude_process_set  = true
    }


  ]
}

# Add Signature rule
resource "ciphertrust_cte_policy_signature_rule" "sig_rule" {
  policy_id             = "csi_policy"
  signature_set_id_list = ["cst3"]
}

# Add Security rule
resource "ciphertrust_cte_policy_security_rule" "key_rule" {
  policy_id = "4c94fe94-fba5-4d46-9389-0e686e550f14"
  rule = {

    effect               = "deny"
    action               = "key_op"
    partial_match        = false
    exclude_resource_set = true
  }
}