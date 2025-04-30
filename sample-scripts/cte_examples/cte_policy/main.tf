terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = ".10.10-beta"
    }
  }
}

provider "ciphertrust" {}


#Creating a STD policy
resource "ciphertrust_cte_policies" "standard_policy" {
  name        = "Std_Policy"
  type        = "Standard"
  description = "Temp policy for testing using terrafrom."
  never_deny  = false
  key_rules {
    key_id = "aes_256_cs1"
  }
  security_rules {
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    exclude_resource_set = true
  }
}

#Creating a LDT policy
resource "ciphertrust_cte_policies" "ldt_policy" {
  name        = "LDT_Policy"
  type        = "LDT"
  description = "Temp policy for testing."
  never_deny  = false
  ldt_key_rules {
    current_key {
      key_id   = "clear_key"
      key_type = ""
    }
    transformation_key {
      key_id   = "aes_256_cs1"
      key_type = ""
    }
  }
  security_rules {
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    exclude_resource_set = true
  }
}

#Creating an IDT policy
resource "ciphertrust_cte_policies" "dx_policy" {
  name        = "IDT_Policy"
  type        = "IDT"
  description = "Temp policy for testing."
  never_deny  = false
  idt_key_rules {
    current_key             = "clear_key"
    current_key_type        = ""
    transformation_key      = "test_aes256_xts"
    transformation_key_type = ""
  }
  security_rules {
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    exclude_resource_set = true
  }
}

#Creating a  Standard DataxForm policy
resource "ciphertrust_cte_policies" "policy" {
  name        = "DxForm_Policy"
  type        = "Standard"
  description = " policy for testing using terrafrom."
  never_deny  = true
  key_rules {
    key_id = "aes_256_cbc_key"
  }

  data_transform_rules {
    key_id          = "clear_key"
    resource_set_id = "resource_set_id"


  }


  security_rules {
    effect               = "deny"
    action               = "read"
    partial_match        = false
    exclude_resource_set = true
    exclude_process_set  = true
  }



}