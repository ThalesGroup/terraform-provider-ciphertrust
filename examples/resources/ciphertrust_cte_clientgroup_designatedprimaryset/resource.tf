# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a CTE Clientgroup designated primary set resource.

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

# Add a resource of type cte clientgroup dps
resource "ciphertrust_cte_clientgroup_designatedprimaryset" "dps1" {

  # ID of the client group where this designated primary set will be configured
  # This references the client group created earlier
  client_group_id = "243b14ec-2251-449d-9ada-6fb1f8e6a414"

  # Name of the designated primary set
  # This acts as an identifier for the DPS configuration
  name = "test"

  # Comma-separated list of clients to be part of the designated primary set
  #
  # NOTE:
  # - Must be provided as a single string (not a list)
  # - All clients listed here MUST already be part of the specified client_group_id
  client_list = "client1,client2"

  # ID/Name of LDT communication group service
  ldt_comm_group_service_id = "ldt-comm-group-name"

}