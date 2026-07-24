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

resource "ciphertrust_cte_client_group" "test_cg_group_test1" {
  name = "test_cgp1"
  cluster_type = "NON-CLUSTER"
  communication_enabled = true
  description = "tf test cg.."

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


  # Whether to inherit attributes from client group
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
  # enable_domain_sharing = true
}











