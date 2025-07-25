terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = "0.11.2"
    }
  }
}

provider "ciphertrust" {}

resource "ciphertrust_cte_client" "test_client_gp" {
  name                     = "test_client1"
  password_creation_method = "GENERATE"
  password                 = "temppass#@#1"
  description              = "Temp host for testing."
  registration_allowed     = true
  communication_enabled    = true
  client_type              = "FS"
}
resource "ciphertrust_cte_policies" "test_policy_gp" {
  name        = "API_Policy"
  type        = "Standard"
  description = "Temp policy for testing using terrafrom."
  never_deny  = true
  security_rules {
    effect               = "permit"
    action               = "all_ops"
    partial_match        = false
    exclude_resource_set = true
  }
}

resource "ciphertrust_cte_policies" "ldt_policy_gp" {
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

resource "ciphertrust_cte_policies" "idt_policy_gp" {
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

#Creating an auto_dir guard point
resource "ciphertrust_cte_guardpoint" "dir_auto_gp" {
  gp_type       = "directory_auto"
  guard_enabled = true
  guard_paths   = ["/test1", "/test2"]
  policy_id     = resource.ciphertrust_cte_client.test_policy_gp.id
  client_id     = resource.ciphertrust_cte_client.test_client_gp.id
}

#Creating a man_dir guard point
resource "ciphertrust_cte_guardpoint" "dir_man_gp" {
  gp_type       = "directory_manual"
  guard_enabled = true
  guard_paths   = ["/test3", "/test4"]
  policy_id     = resource.ciphertrust_cte_client.test_policy_gp.id
  client_id     = resource.ciphertrust_cte_client.test_client_gp.id
}

#Creating a raw_dev_gp guard point
resource "ciphertrust_cte_guardpoint" "raw_dev_gp" {
  gp_type       = "rawdevice_auto"
  guard_enabled = true
  guard_paths   = ["/dev/sdb"]
  policy_id     = "test1"
  client_id     = "hostname"
}

#Creating an auto_dir ldt guard point
resource "ciphertrust_cte_guardpoint" "dir_ldt_auto_gp" {
  gp_type       = "directory_auto"
  guard_enabled = true
  guard_paths   = ["/test5"]
  policy_id     = resource.ciphertrust_cte_client.ldt_policy_gp.id
  client_id     = resource.ciphertrust_cte_client.test_client_gp.id
}

#Creating an auto_dir idt guard point
resource "ciphertrust_cte_guardpoint" "idt_auto_gp" {
  gp_type               = "rawdevice_auto"
  guard_enabled         = true
  guard_paths           = ["/dev/sdc"]
  policy_id             = resource.ciphertrust_cte_client.idt_policy_gp.id
  client_id             = resource.ciphertrust_cte_client.test_client_gp.id
  is_idt_capable_device = true
}