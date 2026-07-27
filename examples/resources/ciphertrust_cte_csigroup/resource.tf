# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE CSIGroup resource
# with the CipherTrust provider, including setting up CTE CSIGroup details.

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

# Create CSI Policy
resource "ciphertrust_cte_policy" "csi_policy1" {
  name        = "csi_policy1"
  policy_type = "CSI"
  never_deny  = true
  key_rules = [{
    key_id = "clear_key"
  }]
  security_rules = [{ effect = "deny" }]
  description    = "Temp CSI policy for testing purpose."
}

resource "ciphertrust_cte_policy" "csi_policy2" {
  name           = "csi_policy2"
  policy_type    = "CSI"
  never_deny     = true
  security_rules = [{ effect = "permit" }]
  description    = "Temp CSI policy for testing purpose."
}


# Create CSI Group
resource "ciphertrust_cte_csigroup" "test_csi_group" {
  name = "TF_CSI_GROUP"

  kubernetes_namespace = "default"

  kubernetes_storage_class = "standard"

  description = "tf test csi group.."

  guard_policies = {
    (ciphertrust_cte_policy.csi_policy1.name) = {},
    (ciphertrust_cte_policy.csi_policy2.name) = {},
  }


  ############################################################
  # Operation type to perform on the CSI Group
  #
  # IMPORTANT:
  # - This field is ONLY used during UPDATE operations
  # - It is IGNORED during the initial `terraform apply`
  #
  # Supported values:
  # - update                : Update description / client_profile
  # - update-guard-policies : Add/remove/Enable/Disable guard policies

  # NOTE:
  # - when op_type = "update-guard-policies" (Using this op_type, we can add new policies or enable/disable/remove existing ones)
  /*
 guard_policies = {
        (ciphertrust_cte_policy.csi_policy1.name) = {},
        (ciphertrust_cte_policy.csi_policy2.name) = {guard_enabled = false},
}
*/

  # UPDATE OPERATIONS
  #
  # NOTE:
  # - Used ONLY when:
  #     op_type = "update"
  # - Only these fields are considered

  /*  
  description    = "updated description"
  client_profile = "updated-profile"
*/

}

# Output the unique ID of the created CTE CSIGroup
output "cte_csigroup_id" {
  value = ciphertrust_cte_csigroup.test_csi_group.id
}