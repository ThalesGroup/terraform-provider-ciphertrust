# Pre-requisites for an Azure certificate - Azure connection, Azure vault.
# This file shows the available options and need not be valid as a whole.

# Provider settings that affect Azure certificates. All are optional.
provider "ciphertrust" {
  cloud_key_manager = {
    azure = {
      # On destroy, purge a certificate after it is soft-deleted, if purge is
      # supported by the vault. Default is true. If false, the certificate is
      # only soft-deleted.
      purge_certificates_on_delete = true

      # If creating a certificate fails because the name belongs to a soft-deleted
      # certificate, recover that certificate instead. Default is false.
      recover_soft_deleted_certificates = false
    }
  }
}

# Native certificate created in the vault.
resource "ciphertrust_azure_certificate" "native" {
  name     = "native-certificate"
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
      lifetime_actions = [
        {
          trigger = {
            days_before_expiry = 30
          }
          action = {
            action_type = "AutoRenew"
          }
        }
      ]
    }
    tags = {
      environment = "test"
    }
  }
}

# Certificate signed by a CipherTrust Manager CA, uploaded to the vault.
# ca_id, source_cert_id and private_key_pem are all required.
# With upload_certificate only azure_params.tags can be set. policy cannot be set.
resource "ciphertrust_azure_certificate" "cm_signed" {
  name     = "cm-signed-certificate"
  vault_id = ciphertrust_azure_vault.vault.id
  azure_params = {
    tags = {
      environment = "dev"
    }
  }
  upload_certificate = {
    source_cert_id  = "cipher-trust-certificate-id"
    ca_id           = "cipher-trust-ca-id"
    private_key_pem = "/path/to/private-key.pem"
  }
}

# External PEM certificate using file paths.
# A PEM certificate needs private_key_pem.
resource "ciphertrust_azure_certificate" "external_pem_files" {
  name     = "external-pem-files"
  vault_id = ciphertrust_azure_vault.vault.id
  upload_certificate = {
    certificate     = "/path/to/certificate.pem"
    private_key_pem = "/path/to/private-key.pem"
  }
}

# External PEM certificate using PEM content from variables.
resource "ciphertrust_azure_certificate" "external_pem_content" {
  name     = "external-pem-content"
  vault_id = ciphertrust_azure_vault.vault.id
  upload_certificate = {
    certificate     = var.certificate_pem
    private_key_pem = var.private_key_pem
  }
}

# External PFX file using a file path.
# A PFX contains the private key, so private_key_pem is not set.
# private_key_password is only needed if the PFX is password protected. It is also used
# for an encrypted private_key_pem.
resource "ciphertrust_azure_certificate" "external_pfx_file" {
  name     = "external-pfx-file"
  vault_id = ciphertrust_azure_vault.vault.id
  upload_certificate = {
    certificate          = "/path/to/certificate.pfx"
    private_key_password = var.private_key_password
  }
}

# External PFX supplied as base64 text, for example from filebase64().
# private_key_password is only needed if the PFX is password protected.
resource "ciphertrust_azure_certificate" "external_pfx_base64" {
  name     = "external-pfx-base64"
  vault_id = ciphertrust_azure_vault.vault.id
  upload_certificate = {
    certificate          = filebase64("/path/to/certificate.pfx")
    private_key_password = var.private_key_password
  }
}

# Restore a purged certificate into a vault from its CipherTrust Manager backup.
# name and azure_params cannot be set.
resource "ciphertrust_azure_certificate" "restored" {
  vault_id = ciphertrust_azure_vault.vault.id
  restore_certificate = {
    certificate_id = "purged-certificate-id"
  }
}
