# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a Cluster of CipherTrust Manager nodes
# with the CipherTrust provider for primary and secondary nodes, including setting up cluster details.

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

# Add a resource of type CM Cluster with three nodes
# Node 10.10.10.11 is the original node in the cluster
# Nodes 10.10.10.12 and 10.10.10.13 are nodes looking to join the cluster
resource "ciphertrust_cluster" "cluster_info" {
  # List of CipherTrust Manager nodes to be added to cluster
  # Original = true would mean that this node is originally in cluster
  # or new cluster operation will happen on this node
	nodes = [
		{
			host = "https://10.10.10.11"
			port = 5432
			original = true
			public_address = "https://10.10.10.11"
			credentials = {
				username = "admin"
				password = "ChangeMe101!"
			}
		},
		{
			host = "https://10.10.10.12"
			port = 5432
			original = false
			public_address = "https://10.10.10.12"
			credentials = {
				username = "admin"
				password = "ChangeMe102!"
			}
		},
		{
			host = "https://10.10.10.13"
			port = 5432
			original = false
			public_address = "https://10.10.10.13"
			credentials = {
				username = "admin"
				password = "ChangeMe103!"
			}
		}
	]
}

# Output the unique ID of the created CM Cluster
output "cluster_id" {
    # The value will be the ID of the CM Cluster resource
    value = ciphertrust_cluster.cluster_info.id
}