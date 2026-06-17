# Pre-requisites - AWS connection and KMS
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "aws-connection-name"
}

data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws_connection,
  ]
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Create an EXTERNAL key in PendingImport state (no source_key_identifier).
# Key material is managed separately by ciphertrust_aws_key_material below.
resource "ciphertrust_aws_byok_key" "ext_key" {
  kms_id = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  aws_param = {
    alias       = ["my-external-key"]
    description = "EXTERNAL key managed via ciphertrust_aws_key_material"
  }
}

# CipherTrust AES key used as the initial key material
resource "ciphertrust_cm_key" "material_v1" {
  name      = "external-key-material-v1"
  algorithm = "AES"
  size      = 256
}

# CipherTrust AES key used as the rotated (replacement) key material
resource "ciphertrust_cm_key" "material_v2" {
  name      = "external-key-material-v2"
  algorithm = "AES"
  size      = 256
}

# Import initial key material to enable the EXTERNAL key.
# The key transitions from PendingImport to Enabled once the first entry is applied.
#
# To rotate the key, add a second key_material entry referencing a new CipherTrust
# source key. On the next apply the provider imports the new material and calls
# rotate-material so the new entry becomes CURRENT and the previous entry moves to
# PREVIOUS state. Remove an entry to delete that material version from the key.
resource "ciphertrust_aws_key_material" "km" {
  aws_key_id = ciphertrust_aws_byok_key.ext_key.key_id

  # Initial material - applied first to enable the key
  key_material {
    source_key_identifier    = ciphertrust_cm_key.material_v1.id
    source_key_tier          = "local"
    key_material_description = "Initial key material - version 1"
  }

  # Rotation material - adding this entry triggers a rotate-material call on the next apply.
  # The key will have two rotation history entries: material_v1 (PREVIOUS) and material_v2 (CURRENT).
  key_material {
    source_key_identifier    = ciphertrust_cm_key.material_v2.id
    source_key_tier          = "local"
    key_material_description = "Rotated key material - version 2"
    valid_to                 = "2030-01-01T00:00:00Z"
  }
}
