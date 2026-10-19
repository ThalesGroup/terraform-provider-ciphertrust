terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.1.0"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-azure-keys-${lower(random_id.random.hex)}"
  native_key_name = "tf-native-${lower(random_id.random.hex)}"
  cm_key_name     = "tf-cm-${lower(random_id.random.hex)}"
  upload_key_name = "tf-upload-${lower(random_id.random.hex)}"
}

# Define an Azure connection
resource "ciphertrust_azure_connection" "connection" {
  name          = local.connection_name
  client_id     = var.azure_client_id
  tenant_id     = var.azure_tenant_id
  client_secret = var.azure_client_secret
  products      = ["cckm"]
}

# Add an existing Azure vault to CipherTrust Manager
resource "ciphertrust_azure_vault" "vault" {
  name            = var.azure_non_purgeable_vault
  connection_id   = ciphertrust_azure_connection.connection.id
  subscription_id = var.azure_subscription_id
}

# Define a native RSA key. The key is created in the Azure vault.
resource "ciphertrust_azure_key" "native_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = local.native_key_name
  azure_params = {
    key = {
      kty     = "RSA"
      key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]
    }
    key_size = 2048
    tags = {
      source = "terraform-sample"
    }
  }
}

# Define a CipherTrust Manager RSA key to upload
resource "ciphertrust_cm_key" "cm_rsa_key" {
  name      = local.cm_key_name
  algorithm = "RSA"
  key_size  = 2048
}

# Upload the CipherTrust Manager key to the Azure vault.
# kty, curve and key_size cannot be set for an uploaded key.
resource "ciphertrust_azure_key" "uploaded_key" {
  vault_id = ciphertrust_azure_vault.vault.id
  name     = local.upload_key_name
  upload_key = {
    source_key_tier = "local"
    source_key_id   = ciphertrust_cm_key.cm_rsa_key.id
  }
  azure_params = {
    key = {
      key_ops = ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"]
    }
  }
}

# Output the whole key. upload_key is left out because it can hold the sensitive pfx_password.
output "native_key" {
  value = {
    for k, v in ciphertrust_azure_key.native_key : k => v
    if k != "upload_key"
  }
}

output "uploaded_key" {
  value = {
    for k, v in ciphertrust_azure_key.uploaded_key : k => v
    if k != "upload_key"
  }
}
