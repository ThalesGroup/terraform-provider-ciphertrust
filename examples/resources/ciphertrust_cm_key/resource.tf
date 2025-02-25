# Terraform Configuration for CipherTrust Provider

# This configuration demonstrates the creation of a 256 bit AES Key
# with the CipherTrust provider, including setting up key details.

terraform {
  # Define the required providers for the configuration
  required_providers {
    # CipherTrust provider for managing CipherTrust resources
    ciphertrust = {
      # The source of the provider
      source = "thalesgroup.com/oss/ciphertrust"
      # Version of the provider to use
      version = "1.0.0"
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

  bootstrap = "no"
}

# Add a resource of type CM Key with the name terraform, algorithm AES and size 256 bits
# This will also use the Users data source to get the User ID from username, terraform
data "ciphertrust_cm_users_list" "list" {
  filters = {
    username = "terraform"
  }
}

resource "ciphertrust_cm_key" "sample_key" {
  # Name of the key
  name="terraform"

  # Cryptographic algorithm this key is used with. Defaults to 'aes'.
  algorithm="aes"

  # Bit length for the key.
  size=256

  # Cryptographic usage mask. Add the usage masks to allow certain usages. Sign (1), Verify (2), Encrypt (4), Decrypt (8), Wrap Key (16), Unwrap Key (32), Export (64), MAC Generate (128), MAC Verify (256), Derive Key (512), Content Commitment (1024), Key Agreement (2048), Certificate Sign (4096), CRL Sign (8192), Generate Cryptogram (16384), Validate Cryptogram (32768), Translate Encrypt (65536), Translate Decrypt (131072), Translate Wrap (262144), Translate Unwrap (524288), FPE Encrypt (1048576), FPE Decrypt (2097152). Add the usage mask values to allow the usages. To set all usage mask bits, use 4194303.
  usage_mask=76

  # Key is deletable
  undeletable=false

  # Key is exportable
  unexportable=false

  # Optional end-user or service data stored with the key
  meta={
    owner_id=tolist(data.ciphertrust_cm_users_list.list.users)[0].user_id
    permissions={
      decrypt_with_key=["CTE Clients"]
      encrypt_with_key=["CTE Clients"]
      export_key=["CTE Clients"]
      mac_verify_with_key=["CTE Clients"]
      mac_with_key=["CTE Clients"]
      read_key=["CTE Clients"]
      sign_verify_with_key=["CTE Clients"]
      sign_with_key=["CTE Clients"]
      use_key=["CTE Clients"]
    }
    cte={
      persistent_on_client=true
      encryption_mode="CBC"
      cte_versioned=false
    }
    xts=false
  }
}

# Output the unique ID of the created CM Key
output "key_id" {
    # The value will be the ID of the CM Key
    value = ciphertrust_cm_key.sample_key.id
}

# Output the name of the created CM Key
output "key_name" {
    # The value will be the name of the CM Key
    value = ciphertrust_cm_key.sample_key.name
}