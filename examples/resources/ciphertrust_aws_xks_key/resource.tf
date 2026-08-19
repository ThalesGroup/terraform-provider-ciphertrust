# Define an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = "name"
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.aws-connection.id
}

# Define a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.aws-connection.id
  name          = "name"
  regions       = data.ciphertrust_aws_account_details.account_details.regions
}

# Define an AES CipherTrust key for creating EXTERNAL_KEY_STORE with CipherTrust Manager as key source
# key should be unexportable, undeletable, symmetric AES 256 key.
resource "ciphertrust_cm_key" "healthcheck_key" {
  name         = "name"
  algorithm    = "AES"
  usage_mask   = 60
  unexportable = true
  undeletable  = true
  # Setting remove_from_state_on_destroy to true will allow the key to be deleted from terraform state on destroy however, it will remain in CipherTrust Manager.
  remove_from_state_on_destroy = true
}

# Define an unlinked external custom keystore with CipherTrust Manager as key source and PUBLIC_ENDPOINT proxy connectivity.
# linked_state is omitted here so the keystore is created unlinked (default). Set linked_state = true to create it linked.
resource "ciphertrust_aws_custom_keystore" "custom_keystore" {
  name   = "name"
  region = "region"
  kms_id = ciphertrust_aws_kms.kms.id
  local_hosted_params = {
    blocked             = false
    health_check_key_id = ciphertrust_cm_key.healthcheck_key.id
    max_credentials     = 8
    source_key_tier     = "local"
  }
  aws_param = {
    xks_proxy_uri_endpoint = "https://demo-xksproxy.thalescpl.io"
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type  = "EXTERNAL_KEY_STORE"
  }
}

# Define a separate AES CipherTrust key to use as the XKS key source.
# Must have the same specs as the health check key: unexportable, undeletable, symmetric AES 256.
resource "ciphertrust_cm_key" "xks_source_key" {
  name                         = "xks-source-key-name"
  algorithm                    = "AES"
  usage_mask                   = 60
  unexportable                 = true
  undeletable                  = true
  remove_from_state_on_destroy = true
}

# Define an unlinked XKS key in the above keystore.
# blocked and linked are both sent to the API at creation time.
# To create a linked key, set linked = true (requires the keystore to also be linked).
# Additional aliases, tags, enable_rotation, and enable_key = false must be set via update after creation.
resource "ciphertrust_aws_xks_key" "xks_key" {
  local_hosted_params = {
    blocked             = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.custom_keystore.id
    linked              = false
    source_key_id       = ciphertrust_cm_key.xks_source_key.id
    source_key_tier     = "local"
  }
  aws_param = {
    alias = ["alias"]
  }
}
