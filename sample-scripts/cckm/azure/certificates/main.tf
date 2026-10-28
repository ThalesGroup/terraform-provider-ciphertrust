terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.1.0"
    }
  }
}

provider "ciphertrust" {
  cloud_key_manager = {
    azure = {
      # The vault does not support purge, so a destroyed certificate is only soft-deleted.
      purge_certificates_on_delete = false
      # Recover a soft-deleted certificate of the same name instead of failing.
      recover_soft_deleted_certificates = true
    }
  }
}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-azure-certs-${lower(random_id.random.hex)}"
  cert_name       = "tf-native-${lower(random_id.random.hex)}"
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

# Define a native self-signed certificate. The certificate is created in the Azure vault.
resource "ciphertrust_azure_certificate" "native" {
  name     = local.cert_name
  vault_id = ciphertrust_azure_vault.vault.id
  azure_params = {
    policy = {
      issuer = {
        name = "Self"
      }
      key_props = {
        kty        = "RSA"
        key_size   = 2048
        exportable = true
        reuse_key  = false
      }
      x509_props = {
        subject         = "CN=example.com"
        validity_months = 12
        sans = {
          dns_names = ["example.com"]
        }
      }
    }
    tags = {
      source = "terraform-sample"
    }
  }
}

# Output the whole certificate. upload_certificate is left out because it can hold
# the sensitive certificate, private_key_pem and private_key_password.
output "certificate" {
  value = {
    for k, v in ciphertrust_azure_certificate.native : k => v
    if k != "upload_certificate"
  }
}
