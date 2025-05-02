# Pre-requisites for EXTERNAL_KEY_STORE and AWS_CLOUDHSM Key store - AWS connection, AWS KMS
# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = "aws_connection_name"
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
  name      = "aes-key-name"
  algorithm = "AES"
  usage_mask = 60
  unexportable = true
  undeletable = true
}
output "cm_aes_key" {
  value = ciphertrust_cm_key.cm_aes_key
}

# Create a policy template using key users and roles
resource "ciphertrust_aws_policy_template" "template_with_users_and_roles" {
  name             = "template-with-users-and-roles-test"
  kms              = ciphertrust_aws_kms.kms.id
  key_admins       = ["dummyadmin"]
  key_admins_roles = ["dummyadminrole"]
  key_users        = ["dummyuser"]
  key_users_roles  = ["dummyuserrole"]
}
output "template_with_users_and_roles" {
  value = ciphertrust_aws_policy_template.template_with_users_and_roles
}

# Create unlinked external custom keystore with CM as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore_for_cm_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_cm_key.cm_aes_key,
  ]
  name = "unlinked-xks-demo-1-for-cm-as-source"
  region = "us-west-1"
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

# Set blocked = true to block above unlinked keystore

# Create an unlinked XKS key with cm as key source in above unlinked external key store
resource "ciphertrust_aws_xks_key" "xks_unlinked_key_with_cm_as_source_1" {
  depends_on = [
    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source,
    ciphertrust_cm_key.cm_aes_key,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
  ]

  local_hosted_params {
    blocked = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source.id
    linked = false
    source_key_id = ciphertrust_cm_key.cm_aes_key.id
    source_key_tier = "local"
  }
  description = "desc for xks_unlinked_key_with_cm_as_source_1"
  alias = ["a1_cm_unlinked_key_1"]
      tags = {
        Tagkey1 = "TagValue1"
        Tagkey2 = "TagValue2"
      }
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

output "xks_unlinked_key_with_cm_as_source_1" {
  value = ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_1
}

# Create linked external custom keystore with CM as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "linked_xks_custom_keystore_for_cm_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_cm_key.cm_aes_key,
  ]
  name = "linked-xks-demo-1-for-cm-as-source"
  region = "us-west-1"
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

# Set connect_disconnect_keystore = CONNECT_KEYSTORE to connect above linked keystore
# Set blocked = true to block above linked keystore

# Create an linked XKS key with cm as key source in above linked external key store
resource "ciphertrust_aws_xks_key" "xks_linked_key_with_cm_as_source_1" {
  depends_on = [
    ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_cm_as_source,
    ciphertrust_cm_key.cm_aes_key,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
  ]

  local_hosted_params {
    blocked = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_cm_as_source.id
    linked = true
    source_key_id = ciphertrust_cm_key.cm_aes_key.id
    source_key_tier = "local"
  }
  description = "desc for xks_linked_key_with_cm_as_source_1"
  alias = ["a1_cm_linked_key_1"]
      tags = {
        Tagkey1 = "TagValue1"
        Tagkey2 = "TagValue2"
      }
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

output "xks_linked_key_with_cm_as_source_1" {
  value = ciphertrust_aws_xks_key.xks_linked_key_with_cm_as_source_1
}

# Create Luna Connection, Luna HSM server, Luna Symmetric key and virtual key for Luna as key source
# Create a hsm network server
resource "ciphertrust_hsm_server" "hsm_server" {
  hostname        = "hsm-ip"
  hsm_certificate = "/path/to/hsm_server_cert.pem"
}

# Create a Luna hsm connection
# is_ha_enabled must be true for more than one partition
resource "ciphertrust_hsm_connection" "hsm_connection" {
  depends_on = [
    ciphertrust_hsm_server.hsm_server,
  ]
  hostname  = "hsm-ip"
  server_id = ciphertrust_hsm_server.hsm_server.id
  name      = "luna-hsm-connection"
  partitions {
    partition_label = "partition-label"
    serial_number   = "serial-number"
  }
  partition_password = "partition-password"
  is_ha_enabled      = false
}
output "hsm_connection_id" {
  value = ciphertrust_hsm_connection.hsm_connection.id
}

# Add a partition to connection
resource "ciphertrust_hsm_partition" "hsm_partition" {
  depends_on = [
    ciphertrust_hsm_connection.hsm_connection,
  ]
  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
}
output "hsm_partition" {
  value = ciphertrust_hsm_partition.hsm_partition
}

# Create an Symmetric AES-256 Luna HSM key for creating EXTERNAL_KEY_STORE with Luna as key source
resource "ciphertrust_hsm_key" "hsm_aes_key" {
  depends_on = [
    ciphertrust_hsm_partition.hsm_partition,
  ]
  attributes = ["CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP", "CKA_UNWRAP"]
  label        = "key-name"
  mechanism    = "CKM_AES_KEY_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 256
  hyok_key     = true
}

output "hsm_aes_key" {
  value = ciphertrust_hsm_key.hsm_aes_key
}

# Create unlinked external custom keystore with luna as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore_for_luna_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_hsm_partition.hsm_partition,
    ciphertrust_hsm_key.hsm_aes_key,
  ]
  name = "unlinked-xks-demo-1-for-luna-as-source"
  region = "us-west-1"
  kms    = ciphertrust_aws_kms.kms.name
  linked_state = false
  connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
  local_hosted_params {
    blocked = false
    health_check_key_id = ciphertrust_hsm_key.hsm_aes_key.id
    max_credentials = 8
    source_key_tier = "hsm-luna"
    partition_id = ciphertrust_hsm_partition.hsm_partition.id
  }
  aws_param {
    xks_proxy_uri_endpoint = "https://demo-xksproxy.thalescpl.io"
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type = "EXTERNAL_KEY_STORE"
  }
}

output "unlinked_xks_custom_keystore_for_luna_as_source" {
  value = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_luna_as_source
}

# Set blocked = true to block above unlinked keystore

# Create a virtual key from above luna key
resource "ciphertrust_virtual_key" "virtual_key_from_luna_key" {
  depends_on = [
    ciphertrust_hsm_key.hsm_aes_key,
  ]
  deletable = false
  source_key_id = ciphertrust_hsm_key.hsm_aes_key.id
  source_key_tier = "hsm-luna"
}
output "virtual_key_from_luna_key" {
  value = ciphertrust_virtual_key.virtual_key_from_luna_key
}

# Create an unlinked XKS key with luna as key source in unlinked key store create above
resource "ciphertrust_aws_xks_key" "xks_unlinked_key_with_luna_as_source_1" {
  depends_on = [
    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_luna_as_source,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
    ciphertrust_virtual_key.virtual_key_from_luna_key,
  ]

  local_hosted_params {
    blocked = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_luna_as_source.id
    linked = false
    source_key_id = ciphertrust_virtual_key.virtual_key_from_luna_key.id
    source_key_tier = "hsm-luna"
  }
  description = "desc for xks_unlinked_key_with_luna_as_source_1"
  alias = ["a1_luna_unlinked_key_1"]
      tags = {
        Tagkey1 = "TagValue1"
        Tagkey2 = "TagValue2"
      }
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

output "xks_unlinked_key_with_luna_as_source_1" {
  value = ciphertrust_aws_xks_key.xks_unlinked_key_with_luna_as_source_1
}

# Set linked = true to create linked keystore/xks key
