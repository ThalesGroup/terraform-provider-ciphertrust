resource "ciphertrust_cte_policies" "standard_policy" {
  name = "API_Policy14"
  type = "Standard"
  description = "Temp policy for testing using terrafrom."
  never_deny = true
  key_rules  {
    key_id = "aes256"
    }
  security_rules  {
    effect = "permit"
    action = "all_ops"
    partial_match = false
    exclude_resource_set = true
    }
}

resource "ciphertrust_cte_policies" "ldt_policy" {
  name = "API_LDT_Policy"
  type = "LDT"
  description = "Temp policy for testing."
  never_deny = false
  ldt_key_rules  {
    current_key  {
      key_id = "clear_key"
      key_type = ""
      }
    transformation_key  {
      key_id = "aes_256_cs1"
      key_type  = "" 
      }
 }
  security_rules  {
    effect = "permit"
    action = "all_ops"
    partial_match = false
    exclude_resource_set = true
    }
}

resource "ciphertrust_cte_policies" "idt_policy" {
  name = "API_IDT_Policy"
  type = "IDT"
  description = "Temp policy for testing."
  never_deny = false
  idt_key_rules  {
    current_key = "clear_key"
    current_key_type = ""
    transformation_key = "test_aes256_xts"
    transformation_key_type  = "" 
 }
  security_rules  {
    effect = "permit"
    action = "all_ops"
    partial_match = false
    exclude_resource_set = true
    }
}