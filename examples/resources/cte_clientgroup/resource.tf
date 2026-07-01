# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE Clientgroup resource
# with the CipherTrust provider, including setting up cliengroup details.

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

# Add a resource of type CTE  Client Group
resource "ciphertrust_cte_client_group" "test_cg_group_test1" {
  name = "test_cgp1"                # Name of the client group

  cluster_type = "NON-CLUSTER"      # Type of cluster (e.g., CLUSTER / NON-CLUSTER)

  communication_enabled = true      # Enable/disable communication for this group

  description = "tf test cg.."      # Optional description for the client group

  # - List of clients to be added to client group
  client_list = [
    "client1",  # Client hostname or identifier
    "client2"      # Client IP address
  ]

  # Operation type to perform on the client group
  #
  # IMPORTANT:
  # - This field is ONLY used during UPDATE operations
  # - It is IGNORED during the initial `terraform apply` (resource creation)
  #
  # Supported values:
  # - add-client       : Add clients to the group
  # - remove-client    : Remove clients from the group
  # - update           : Update group-level properties
  # - update-password  : Update client password
  # - reset-password   : Reset client password
  # - auth-binaries    : Configure authorized binaries

 # op_type = "add-client/remove-client/update/update-password/reset-password/auth-binaries"

  # List of clients to operate on
  #
  # NOTE:
  # - Used ONLY for client-related operations:
  #     add-client, remove-client
  # - Ignored for other op_type values
  # - Add/remove clients from client_list based on operation type



  # Whether to inherit attributes from parent client group
  #
  # NOTE:
  # - Applicable ONLY when op_type = "add-client"
  # - Ignored for all other operations

  # inherit_attributes = true

  #NOTE:
  # - These three fields are applicable ONLY when op_type = update
  # - Ignored for all other operations

  # client_locked = true
  # system_locked = true
  #enable_domain_sharing = true
}

# Output the unique ID of the created CTE Client Group
output "cte_client_group_id" {
    value = ciphertrust_cte_client_group.test_cg_group_test1.id
}