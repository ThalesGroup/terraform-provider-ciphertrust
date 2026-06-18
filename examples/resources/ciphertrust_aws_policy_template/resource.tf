# Define an AWS connection
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "aws-connection-name"
}

data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

# Assign a ciphertrust_aws_kms resource to the connection
resource "ciphertrust_aws_kms" "kms" {
  account_id     = "account-id"
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Define a policy template using key_admins and key_users
resource "ciphertrust_aws_policy_template" "policy_template_ex1" {
  key_admins = ["aws-iam-user", "aws-iam-role"]
  key_users  = ["aws-iam-user", "aws-iam-role"]
  km         = kms.id
}

# Define a policy template using a policy json
resource "ciphertrust_aws_policy_template" "policy_template_ex2" {
  km     = kms.id
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

# Define an AWS key and assign the key policy template to it
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
  policy {
    policy_template = ciphertrust_aws_policy_template.policy_template_ex1.id
  }
}
