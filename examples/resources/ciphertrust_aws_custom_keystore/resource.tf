# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = "aws_connection_name"
}
output "aws_connection_id" {
  value = ciphertrust_aws_connection.aws-connection.id
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws-connection.id
}

# Create a kms
resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws-connection,
  ]
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Create an AES CipherTrust key for creating EXTERNAL_KEY_STORE with CM as key source
# key should be unexportable, undeletable, symmetric AES 256 key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name         = "aes-key-name"
  algorithm    = "AES"
  usage_mask   = 60
  unexportable = true
  undeletable  = true
  remove_from_state_on_destroy = true
}
output "cm_aes_key" {
  value = ciphertrust_cm_key.cm_aes_key
}

# Create unlinked external custom keystore with CM as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore_for_cm_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_cm_key.cm_aes_key,
  ]
  name = "unlinked-xks-demo-1-for-cm-as-source"
  region = ciphertrust_aws_kms.kms.regions[0]
  kms    = ciphertrust_aws_kms.kms.name
  linked_state = false
  connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
  local_hosted_params {
    blocked = false
    health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
    max_credentials = 8
    source_key_tier = "local"
  }
  aws_param {
    xks_proxy_uri_endpoint = "https://demo-xksproxy.thalescpl.io"
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type = "EXTERNAL_KEY_STORE"
  }
}

output "unlinked_xks_custom_keystore_for_cm_as_source" {
  value = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source
}

# Create linked external custom keystore with CM as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "linked_xks_custom_keystore_for_cm_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_cm_key.cm_aes_key,
  ]
  name = "linked-xks-demo-1-for-cm-as-source"
  region = ciphertrust_aws_kms.kms.regions[0]
  kms    = ciphertrust_aws_kms.kms.name
  linked_state = true
  connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
  local_hosted_params {
    blocked = false
    health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
    max_credentials = 8
    source_key_tier = "local"
  }
  aws_param {
    xks_proxy_uri_endpoint = "https://demo-xksproxy.thalescpl.io"
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type = "EXTERNAL_KEY_STORE"
  }
}

output "linked_xks_custom_keystore_for_cm_as_source" {
  value = ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_cm_as_source
}
