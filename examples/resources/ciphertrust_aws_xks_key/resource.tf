# Define an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name              = "aws_connection_name"
  access_key_id     = "access-key-id"
  secret_access_key = "secret-access-key"
}
output "aws_connection_id" {
  value = ciphertrust_aws_connection.aws-connection.id
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws-connection.id
}

# Define a kms
resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws-connection,
  ]
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Define an AES CipherTrust key for creating EXTERNAL_KEY_STORE with CM as key source
# key should be unexportable, undeletable, symmetric AES 256 key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name         = "aes-key-name"
  algorithm    = "AES"
  usage_mask   = 60
  unexportable = true
  undeletable  = true
}

# Define a policy template using key users and roles
resource "ciphertrust_aws_policy_template" "template_with_users_and_roles" {
  name             = "template-with-users-and-roles-test"
  kms              = ciphertrust_aws_kms.kms.id
  key_admins       = ["key-admins"]
  key_admins_roles = ["key-admins-roles"]
  key_users        = ["key-users"]
  key_users_roles  = ["key-users-roles"]
}

# Define unlinked external custom keystore with CM as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore_for_cm_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_cm_key.cm_aes_key,
  ]
  name                        = "unlinked-xks-demo-1-for-cm-as-source"
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

# Set blocked = true to block above unlinked keystore

# Define an unlinked XKS key with cm as key source in above unlinked external key store
resource "ciphertrust_aws_xks_key" "xks_unlinked_key_with_cm_as_source_1" {
  depends_on = [
    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source,
    ciphertrust_cm_key.cm_aes_key,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
  ]

  local_hosted_params {
    blocked             = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source.id
    linked              = false
    source_key_id       = ciphertrust_cm_key.cm_aes_key.id
    source_key_tier     = "local"
  }
  description = "desc for xks_unlinked_key_with_cm_as_source_1"
  alias       = ["a1_cm_unlinked_key_1"]
  tags = {
    Tagkey1 = "TagValue1"
    Tagkey2 = "TagValue2"
  }
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

# Define linked external custom keystore with CM as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "linked_xks_custom_keystore_for_cm_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_cm_key.cm_aes_key,
  ]
  name                        = "linked-xks-demo-1-for-cm-as-source"
  region                      = ciphertrust_aws_kms.kms.regions[0]
  kms                         = ciphertrust_aws_kms.kms.name
  linked_state                = true
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

# Set connect_disconnect_keystore = CONNECT_KEYSTORE to connect above linked keystore
# Set blocked = true to block above linked keystore

# Define an linked XKS key with cm as key source in above linked external key store
resource "ciphertrust_aws_xks_key" "xks_linked_key_with_cm_as_source_1" {
  depends_on = [
    ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_cm_as_source,
    ciphertrust_cm_key.cm_aes_key,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
  ]

  local_hosted_params {
    blocked             = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_cm_as_source.id
    linked              = true
    source_key_id       = ciphertrust_cm_key.cm_aes_key.id
    source_key_tier     = "local"
  }
  description = "desc for xks_linked_key_with_cm_as_source_1"
  alias       = ["a1_cm_linked_key_1"]
  tags = {
    Tagkey1 = "TagValue1"
    Tagkey2 = "TagValue2"
  }
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

# Set linked = true to create linked keystore/xks key
