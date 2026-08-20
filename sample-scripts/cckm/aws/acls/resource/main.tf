terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.1"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name = "tf-acl-${lower(random_id.random.hex)}"
  kms_name        = "tf-acl-${lower(random_id.random.hex)}"
  user_name       = "tf-acl-user-${lower(random_id.random.hex)}"
  group_name      = "tf-acl-group-${lower(random_id.random.hex)}"
  user_password   = "Secure-${upper(random_id.random.hex)}-1!"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "connection" {
  name = local.connection_name
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.connection.id
}

# Create a KMS
resource "ciphertrust_aws_kms" "kms" {
  name          = local.kms_name
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.connection.id
  regions       = [data.ciphertrust_aws_account_details.account_details.regions[0]]
}

# Create a CipherTrust Manager user
resource "ciphertrust_user" "user" {
  username = local.user_name
  password = local.user_password
}

# Create an ACL granting the user key-create and key-delete on the KMS
resource "ciphertrust_aws_acl" "user_acl" {
  kms_id  = ciphertrust_aws_kms.kms.id
  user_id = ciphertrust_user.user.id
  actions = ["keycreate", "keydelete"]
}

# Create a CipherTrust Manager group
resource "ciphertrust_groups" "group" {
  name = local.group_name
}

# Create an ACL granting the group key-create, key-update, and key-delete on the KMS
resource "ciphertrust_aws_acl" "group_acl" {
  kms_id  = ciphertrust_aws_kms.kms.id
  group   = ciphertrust_groups.group.id
  actions = ["keycreate", "keyupdate", "keydelete"]
}

# List the KMS - the output includes the acls array showing all ACL entries
data "ciphertrust_aws_kms_list" "kms" {
  depends_on = [ciphertrust_aws_acl.user_acl, ciphertrust_aws_acl.group_acl]
  filters = {
    name = ciphertrust_aws_kms.kms.name
  }
}
output "kms" {
  value = data.ciphertrust_aws_kms_list.kms
}
