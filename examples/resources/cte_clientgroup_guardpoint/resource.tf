# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE Client group guardpoint resource
# with the CipherTrust provider, including setting up guardpoint details.

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

# Add a resource of type CTE guardpoint to guard paths /test1 and /test2
resource "ciphertrust_cte_clientgroup_guardpoint" "dir_auto_gp_cg" {

   # ID of client group
  client_group_id = ciphertrust_cte_client_group.cte_client_group.id

  guard_points = {

    # guard_path and its params are sent as a map
    "/test/gp_cg1" = {
      guard_point_params = {

        # Type of the GuardPoint. The valid values are “directory_auto”, “directory_manual”, “rawdevice_manual”, “rawdevice_auto”, “cloudstorage_auto”, “cloudstorage_manual”, or "ransomware_protection".

        guard_point_type = "directory_auto"

         # ID/Name of the policy applied with this GuardPoint
        policy_id        = ciphertrust_cte_policy.standard_policy.id
        
        # These fields are ignored during intitial apply but can be updated, their default values are set (mfa_enabled=false, guard_enabled-true)
        #mfa_enabled = true
        #guard_enabled = false
      }
    }
  }
}

# Output the unique ID of the created CTE GuardPoint
output "guardpoint_id" {
    value = ciphertrust_cte_clientgroup_guardpoint.dir_auto_gp.id
}