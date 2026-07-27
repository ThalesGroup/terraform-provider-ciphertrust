# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE Client Policy resource
# with the CipherTrust provider, including setting up policy details.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "ThalesGroup/CipherTrust"
      # Version of the provider to use
      version = "1.0.0-pre3"
    }
  }
}

# Configure the CipherTrust provider for authentication
provider "ciphertrust" {
  # The address of the CipherTrust appliance (replace with the actual address)
  address = "https://10.10.10.10"

  # Username for authenticating with the CipherTrust appliance
  username = "admin"

  # Password for authenticating with the CipherTrust appliance
  password = "ChangeMe101!"
}

# Add Standard policy
resource "ciphertrust_cte_policy" "std_policy" {
  name        = "std_policy"
  policy_type = "Standard"
  description = "Created via TF"
  never_deny  = true
  security_rules = [{
    effect        = "permit,audit"
    action        = "all_ops"
    partial_match = false
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
    effect = "permit"
    action = "all_ops"
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
    effect        = "permit"
    action        = "all_ops"
    partial_match = false
    }
  ]

}

# Add Dxt policy rule
resource "ciphertrust_cte_policy" "dxt_policy" {
  name        = "DxForm_Policy"
  policy_type = "Standard"
  description = " policy for testing using terrafrom..."
  never_deny  = true
  key_rules   = [{ key_id = "clear_key" }]

  data_transform_rules = [{
    key_id = "clear_key"
  }]

  security_rules = [{
    effect = "permit"
    action = "key_op"
    }
  ]
}

# Add COS policy
resource "ciphertrust_cte_policy" "cos_policy" {
  name        = "cos_policy"
  policy_type = "Cloud_Object_Storage"
  never_deny  = true

  key_rules = [{
    key_id = "cos_key"
  }]


  metadata = {
    restrict_update = false
  }

  security_rules = [{ effect = "deny" }]
  description    = "Temp COS policy for testing purpose."
}

# Add CSI policy
resource "ciphertrust_cte_policy" "csi_policy" {
  name        = "csi_policy"
  policy_type = "CSI"
  never_deny  = true

  key_rules = [{
    key_id = "clear_key"
  }]

  metadata = {
    restrict_update = false
  }

  security_rules  = [{ effect = "deny" }]
  signature_rules = [{ signature_set_id = "signset-containerimge-36446638" }]
  description     = "Temp CSI policy for testing purpose."
}


# Output the unique ID of the created CTE Policies 
output "policy_id" {
  value = ciphertrust_cte_policy.std_policy.id
}