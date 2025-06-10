terraform {
  required_providers {
    ciphertrust = {
      source  = "thales.com/terraform/ciphertrust"
      version = ">= 1.0.0"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  oci_key_file        = "/work/terraform_server_certs/oci-key-file.pem"
  pubkey_fingerprint  = "c6:eb:b9:b1:22:8b:39:79:80:60:16:33:9b:e3:c9:ec"
  region              = "us-ashburn-1"
  tenancy_ocid        = "ocid1.tenancy.oc1..aaaaaaaadixb52q2mvlsn634ql5aaal6hb2vg7audpd4d4mcf5zluymff6sq"
  user_ocid           = "ocid1.user.oc1..aaaaaaaam5qlu6nxoyi4nhewduivm2e7n4ye4dwdk5jcwxvoz2arfjtr5e3q"
  vault_ocid          = "ocid1.vault.oc1.iad.bzqyzunhaagyg.abuwcljrlzpbjpufvqp366jzmcr3txtbz7dximukyazav4hyzgbpdtd7qnea"
  compartment_ocid    = "ocid1.compartment.oc1..aaaaaaaasys76jxn2mrjb534orknwrwfe3npr4tfba7npxnal7whxiiztzva"
  connection_name     = "tf-${lower(random_id.random.hex)}"
  cm_key_name         = "tf-${lower(random_id.random.hex)}"
  oci_key_name        = "tf-${lower(random_id.random.hex)}"
  cm_key_version_name = "tf-ver-${lower(random_id.random.hex)}"
}

# Define an OCI connection
resource "ciphertrust_oci_connection" "oci_connection" {
  key_file            = local.oci_key_file
  name                = local.connection_name
  pub_key_fingerprint = local.pubkey_fingerprint
  region              = local.region
  tenancy_ocid        = local.tenancy_ocid
  user_ocid           = local.user_ocid

}

# Define an OCI vault
resource "ciphertrust_oci_vault" "vault" {
  connection_id = ciphertrust_oci_connection.oci_connection.id
  vault_id      = local.vault_ocid
  region        = local.region
}

# Define an RSA CipherTrust key
resource "ciphertrust_cm_key" "cm_rsa_key" {
  name       = local.cm_key_name
  algorithm  = "RSA"
  usage_mask = 60
  key_size   = 2048
}

# Define an OCI byok key
resource "ciphertrust_oci_byok_key" "byok_key" {
  name = local.oci_key_name
  oci_key_params = {
    compartment_id  = local.compartment_ocid
    protection_mode = "SOFTWARE"
  }
  source_key_id   = ciphertrust_cm_key.cm_rsa_key.id
  source_key_tier = "local"
  vault           = ciphertrust_oci_vault.vault.id
}

# Define an AES CipherTrust key for the key version
resource "ciphertrust_cm_key" "cm_rsa_version" {
  name       = local.cm_key_version_name
  algorithm  = "RSA"
  usage_mask = 60
  key_size   = 2048
}

# Add a byok key version to the key
resource "ciphertrust_oci_byok_key_version" "byok_version" {
  cckm_key_id   = ciphertrust_oci_byok_key.byok_key.id
  source_key_id = ciphertrust_cm_key.cm_rsa_version.id
}
output "byok_version" {
  value = ciphertrust_oci_byok_key_version.byok_version
}

# Add a native version to the key
resource "ciphertrust_oci_key_version" "native_version" {
  cckm_key_id = ciphertrust_oci_byok_key.byok_key.id
}
output "native_version" {
  value = ciphertrust_oci_key_version.native_version
}

# List all OCI key versions of the key
data "ciphertrust_oci_key_version_list" "ds_versions" {
  key_id     = ciphertrust_oci_byok_key.byok_key.id
  depends_on = [ciphertrust_oci_key_version.native_version, ciphertrust_oci_byok_key_version.byok_version]
}
output "version_list" {
  value = data.ciphertrust_oci_key_version_list.ds_versions
}

# List the key
data "ciphertrust_oci_key_list" "ds_key" {
  filters = {
    id = ciphertrust_oci_byok_key.byok_key.id
  }
  depends_on = [ciphertrust_oci_key_version.native_version, ciphertrust_oci_byok_key_version.byok_version]
}
output "key_list" {
  value = data.ciphertrust_oci_key_list.ds_key
}
