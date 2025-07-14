# Define an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = "connection-name"
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws-connection.id
}

# Define a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Define an AES CipherTrust key for creating EXTERNAL_KEY_STORE with CipherTrust Manager as key source
# key should be unexportable, undeletable, symmetric AES 256 key.
resource "ciphertrust_cm_key" "cm_aes_key" {
  name         = "aes-key-name"
  algorithm    = "AES"
  usage_mask   = 60
  unexportable = true
  undeletable  = true
  # Setting remove_from_state_on_destroy to true will allow the key to be deleted from terraform state on destroy however, it will remain in CipherTrust Manager.
  remove_from_state_on_destroy = true
}

# Define unlinked external custom keystore with CipherTrust Manager as key source and PUBLIC_ENDPOINT proxy connectivity
resource "ciphertrust_aws_custom_keystore" "custom_keystore" {
  name                        = "keystore-name"
  region                      = "us-west-1"
  kms                         = ciphertrust_aws_kms.kms.name
  linked_state                = false
  connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
  local_hosted_params {
    blocked             = false
    health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
    max_credentials     = 8
    source_key_tier     = "local"
  }
  aws_param {
    xks_proxy_uri_endpoint = "https://demo-xksproxy.thalescpl.io"
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type  = "EXTERNAL_KEY_STORE"
  }
}

# Define an unlinked XKS key with CipherTrust Manager as key source in above unlinked external key store
# Keys can only be linked once the keystore is linked
resource "ciphertrust_aws_xks_key" "xks_key" {
  alias = ["key-name"]
  local_hosted_params {
    blocked             = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.custom_keystore.id
    linked              = false
    source_key_id       = ciphertrust_cm_key.cm_aes_key.id
    source_key_tier     = "local"
  }
}

# An example resource for importing an existing xks key
resource "ciphertrust_aws_xks_key" "imported_xks_key" {
  local_hosted_params {
    blocked             = false
    custom_key_store_id = "0813e489-6930-4c4f-a9ab-85ff275f9122"
    linked              = false
    source_key_id       = "5b0cce40a9434708bfb2510a670dce2d12a0253bda444a109224e519f0df5619"
    source_key_tier     = "local"
  }
}
