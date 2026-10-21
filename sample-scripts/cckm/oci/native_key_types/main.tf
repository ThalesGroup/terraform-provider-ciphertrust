terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.1.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-oci-types-${lower(random_id.random.hex)}"
  aes_key_name    = "tf-oci-aes-${lower(random_id.random.hex)}"
  rsa_key_name    = "tf-oci-rsa-${lower(random_id.random.hex)}"
  ecdsa_key_name  = "tf-oci-ecdsa-${lower(random_id.random.hex)}"
}

# Define an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = var.oci_key_file
  name                = local.connection_name
  pub_key_fingerprint = var.oci_pub_key_fingerprint
  region              = var.oci_region
  tenancy_ocid        = var.oci_tenancy_ocid
  user_ocid           = var.oci_user_ocid
}

# Define an OCI vault
resource "ciphertrust_oci_vault" "vault" {
  connection_id = ciphertrust_oci_connection.oci_connection.id
  vault_id      = var.oci_vault_ocid
  region        = var.oci_region
}

# AES native key with freeform tags and a custom deletion wait.
# length is in bytes: 16, 24 or 32.
# schedule_for_deletion_days is used when the key is destroyed (7 to 30).
resource "ciphertrust_oci_key" "aes_key" {
  name  = local.aes_key_name
  vault = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    algorithm       = "AES"
    compartment_id  = ciphertrust_oci_vault.vault.compartment_id
    length          = 32
    protection_mode = var.oci_protection_mode
    freeform_tags = {
      created_by = "terraform"
      purpose    = "sample"
    }
    # defined_tags require an existing OCI tag namespace. Uncomment and edit to use them.
    # defined_tags = [
    #   {
    #     tag    = "my-namespace"
    #     values = { my-tag = "my-value" }
    #   }
    # ]
  }
  schedule_for_deletion_days = 8
}

# RSA native key. length is in bytes: 256 (2048 bit), 384 (3072 bit) or 512 (4096 bit).
resource "ciphertrust_oci_key" "rsa_key" {
  name  = local.rsa_key_name
  vault = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    algorithm       = "RSA"
    compartment_id  = ciphertrust_oci_vault.vault.compartment_id
    length          = 256
    protection_mode = var.oci_protection_mode
  }
}

# ECDSA native key. curve_id is required for ECDSA.
# length is in bytes and must match the curve: NIST_P256 (32), NIST_P384 (48), NIST_P521 (66).
resource "ciphertrust_oci_key" "ecdsa_key" {
  name  = local.ecdsa_key_name
  vault = ciphertrust_oci_vault.vault.id
  oci_key_params = {
    algorithm       = "ECDSA"
    compartment_id  = ciphertrust_oci_vault.vault.compartment_id
    curve_id        = "NIST_P256"
    length          = 32
    protection_mode = var.oci_protection_mode
  }
}

# To restore an HSM key from its most recent OCI backup, add this argument to a key resource
# and change its value on each restore. It applies only to HSM keys in a Virtual Private Vault
# that has a backup bucket configured.
# restore_from_backup_trigger = "1"

# List the keys created above
data "ciphertrust_oci_key_list" "sample_keys" {
  filters = {
    key_name = local.aes_key_name
  }
  depends_on = [ciphertrust_oci_key.aes_key, ciphertrust_oci_key.rsa_key, ciphertrust_oci_key.ecdsa_key]
}
output "key_list" {
  value = data.ciphertrust_oci_key_list.sample_keys
}
