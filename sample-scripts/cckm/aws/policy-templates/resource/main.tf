terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "1.0.0-pre3"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  connection_name                    = "tf-pt-${lower(random_id.random.hex)}"
  kms_name                           = "tf-pt-${lower(random_id.random.hex)}"
  key_with_policy_name               = "tf-pt-policy-${lower(random_id.random.hex)}"
  key_with_users_and_roles_name      = "tf-pt-users-and-roles-${lower(random_id.random.hex)}"
  template_with_policy_name          = "tf-pt-policy-${lower(random_id.random.hex)}"
  template_with_users_and_roles_name = "tf-pt-users-and-roles-${lower(random_id.random.hex)}"
  user                               = "aws-iam-user"
  admin                              = "aws-iam-admin"
  user_role                          = "aws-iam-user-role"
  admin_role                         = "aws-iam-admin-role"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = local.connection_name
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
  name             = local.template_with_users_and_roles_name
  kms              = ciphertrust_aws_kms.kms.id
  key_admins       = [local.admin]
  key_admins_roles = [local.admin_role]
  key_users        = [local.user]
  key_users_roles  = [local.user_role]
}

# Create an AWS key and assign a policy template to it
resource "ciphertrust_aws_key" "aws_key_with_users_and_roles" {
  alias  = [local.key_with_users_and_roles_name]
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

# Create a policy template using a policy json
resource "ciphertrust_aws_policy_template" "template_with_policy" {
  name = local.template_with_policy_name
  kms  = ciphertrust_aws_kms.kms.id
  policy = jsonencode(
    {
      "Version" : "2012-10-17",
      "Id" : "kms-tf-1",
      "Statement" : [{
        "Sid" : "Enable IAM User Permissions 1",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "*"
        },
        "Action" : "kms:*",
        "Resource" : "*"
      }]
    }
  )
}

# Create an AWS key and assign a policy template to it
resource "ciphertrust_aws_key" "aws_key_with_policy" {
  alias  = [local.key_with_policy_name]
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_policy.id
  }
}
