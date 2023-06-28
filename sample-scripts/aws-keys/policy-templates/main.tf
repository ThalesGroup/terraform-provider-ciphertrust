terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = ".10.0-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name               = "aws-connection-${lower(random_id.random.hex)}"
  kms_name                      = "kms-${lower(random_id.random.hex)}"
  key_with_policy_name          = "aws-key-with-policy-${lower(random_id.random.hex)}"
  key_with_users_and_roles_name = "aws-key-with-users-and-roles-${lower(random_id.random.hex)}"
  template_with_policy_name     = "template-with-policy-${lower(random_id.random.hex)}"
  template_with_users_and_roles = "template-with-users-and-roles-${lower(random_id.random.hex)}"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = local.connection_name
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
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = local.kms_name
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Create a policy template using key users and roles
resource "ciphertrust_aws_policy_template" "template_with_users_and_roles" {
  name             = local.template_with_users_and_roles
  kms              = ciphertrust_aws_kms.kms.id
  key_admins       = [var.admin]
  key_admins_roles = [var.admin_role]
  key_users        = [var.user]
  key_users_roles  = [var.user_role]
}
output "template_with_users_and_roles" {
  value = ciphertrust_aws_policy_template.template_with_users_and_roles
}

# Create an AWS key and assign a policy template to it
resource "ciphertrust_aws_key" "aws_key_with_users_and_roles" {
  alias  = [local.key_with_users_and_roles_name]
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
  tags = {
    TagKey = "TagValue"
  }
}
output "aws_key_with_users_and_roles_policy" {
  value = ciphertrust_aws_key.aws_key_with_users_and_roles.policy
}
output "aws_key_with_users_and_roles_id" {
  value = ciphertrust_aws_key.aws_key_with_users_and_roles.id
}
output "aws_key_with_users_and_roles_tags" {
  value = ciphertrust_aws_key.aws_key_with_users_and_roles.tags
}
output "aws_key_with_users_and_rolespolicy_template_tag" {
  value = ciphertrust_aws_key.aws_key_with_users_and_roles.policy_template_tag
}

# Create a policy template using a policy json
resource "ciphertrust_aws_policy_template" "template_with_policy" {
  name   = local.template_with_policy_name
  kms    = ciphertrust_aws_kms.kms.id
  policy = <<-EOT
  {
    "Version": "2012-10-17",
    "Id": "kms-tf-1",
    "Statement": [{
      "Sid": "Enable IAM User Permissions 1",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": "kms:*",
      "Resource": "*"
    }]
  }
  EOT
}
output "template_with_policy" {
  value = ciphertrust_aws_policy_template.template_with_policy
}

# Create an AWS key and assign a policy template to it
resource "ciphertrust_aws_key" "aws_key_with_policy" {
  alias  = [local.key_with_policy_name]
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_policy.id
  }
  tags = {
    TagKey = "TagValue"
  }
}
output "aws_key_with_policy" {
  value = ciphertrust_aws_key.aws_key_with_policy.policy
}
output "aws_key_with_policy_id" {
  value = ciphertrust_aws_key.aws_key_with_policy.id
}
output "aws_key_with_policy_tags" {
  value = ciphertrust_aws_key.aws_key_with_policy.tags
}
output "aws_key_with_policy_policy_template_tag" {
  value = ciphertrust_aws_key.aws_key_with_policy.policy_template_tag
}
