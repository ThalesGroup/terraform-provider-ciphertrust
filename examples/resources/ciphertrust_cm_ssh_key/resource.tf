# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates adding an SSH Key resource
# with the CipherTrust provider, including setting up SSH Key details.

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

  bootstrap = "yes"
}

# Add a resource of type CM SSH Key with a sample key
resource "ciphertrust_cm_ssh_key" "ssh_key" {
    key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDIVGP8Ojyum6d7/r2Q1oihXfEcmEgzKUOCcNue2ovIRaxnqdFBTIEVnPBu6R0kMvBHvhyYpqQaLyCa6QhYgmzLA16A7M0+QSdBz+pFC6cMF6VK9b/lXgLek3aD4s+ynCc+/RF+n2AcS5j+JmkvQeOntY/WhmvCwJJpk6cmNfpnqfF/C8ExvGC3IPBCaVtHU2eIHvT0rIVwGYNZulrryeoPQZ2vH4cUPCDHxFeWTGCjXxPvy0JSoY0Z5mKJtxWLnEgIFzTUYiDueKM7HTrj5LPzov3ohB5bhNdiA+wLljFL7da8OvNhXp6aqCgg9ezs8df3bNSkWiaf24R/28sTeDuF"
}

# Output the unique ID of the created SSH Key
output "key_id" {
    # The value will be the ID of the SSH Key resource
    value = ciphertrust_cm_ssh_key.ssh_key.id
}