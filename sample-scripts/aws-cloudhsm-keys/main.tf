terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/ciphertrust"
      version = "0.10.7-beta"
    }
  }
}

provider "ciphertrust" {}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  aws_connection_name = "aws-connection-${lower(random_id.random.hex)}"
  kms_name        = "kms-${lower(random_id.random.hex)}"
  template_with_users_and_roles = "template-with-users-and-roles-${lower(random_id.random.hex)}"
}

# Create an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = local.aws_connection_name
  access_key_id     = var.access_key_id
  secret_access_key = var.secret_access_key
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
  name           = local.kms_name
  regions        = [var.cks_region]
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

# Create cloudHSM keystore
resource "ciphertrust_aws_custom_keystore" "cloudhsm_custom_keystore" {
  depends_on = [
    ciphertrust_aws_kms.kms,
  ]
  name         = "cloudhsm-keystore-demo-1"
  region       = var.cks_region
  kms          = ciphertrust_aws_kms.kms.name
  linked_state = var.cks_linked
  connect_disconnect_keystore = var.cks_aws_cks_connect_disconnect_state
  aws_param {
    custom_key_store_type       = var.cks_aws_xks_custom_keystore_type
    cloud_hsm_cluster_id        = var.cks_aws_cloudhsm_keystore_hsm_cluster_id
    key_store_password          = var.cks_aws_cloudhsm_keystore_password
    trust_anchor_certificate    = <<-EOT
                     -----BEGIN CERTIFICATE-----
                     MIIDhzCCAm+gAwIBAgIUHdJu4algAFs12h87meBhd9Qe4rMwDQYJKoZIhvcNAQEL
                     BQAwUzELMAkGA1UEBhMCVVMxCzAJCgNVBAgMAkNBMRAwDgYDVQQHDAdTYW5Kb3Nl
                     MQ8wDQYDVQQKDAZUaGFsZXMxFDASBgNVBAsMC0VuZ2luZWVyaW5nMB4XDTIyMDYy
                     MzA2NTgwOFoXFTMyMDYyMjA2NTgwOFosUzEMMAkGA1UEBhMCVVNxCzAJBgNVBAgM
                     AkNBMRAwDgYCVQQHDAdTYW5Kb3NlMQ8wDQYDVQQKDAZUaGFsZXMxFDASBgNVBAsM
                     C0VuZ2luZWVyaW5nMIIBIjANBgkqhabG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvi0o
                     wtYFziFlahtH0X0+0fhvcGLJ4SYTOU50ZGb7GlfsKC4i5vGxXFEJ1QwJ+WmkyXwo
                     RCWaXQbFkFIxlDDIgOe64Z8FRiqdRGXPAYWvJC5pM015kOGtuMrT759Ifbux81Ng
                     ULlUbz7uLGxut+IbLXIG+/lkDI8OtYNLtU4hbTG/QrTieFg7ZQ/IKKbmCKB3m2cv
                     l0MzSMZQXMgNmsbbdSATTgSgaBdAF23sp3B78jHFDpikZHvrxjPBRqi/OsSBefmV
                     LymMhPBVdF9FWJgL+YpxDjKP4ieo8rqWK9zEDnu6VmVx0guQ40uM4ycaDljBueW6
                     J9FqXFp62FGrGKu2vwIDAQABo1MwUTAdBgNVHQ4EFgQUi/RAIOrEPaUm9T4P+Ju3
                     qTKpf90wHwYDVR0jBBgwFoATi/RAIOrEPaUm9T6P+Ju3qTKpf90wDwYDVR0TAQH/
                     BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAfhC8EghStmPq770Edt6lfoEC6pIO
                     UCMoiwnX9KL7WdKPx7auyJmxj3+MbYqNSzilXPA57J1WE6BhT3JOT4nPsO/IpFv2
                     fbpUVW9ypwqRQE1S1v6BjvQd5J59c3ZDfH634jCwGwxcBY2gSbZorLb03aH7R2uF
                     31jlyotNbUd3eWjo11jwVt9ZhpdxbaiK98Q6UdUro0Ok2BaQdZZthnuMMnwK8iO2
                     w3XiEJU3ucUbs1jC6x2Q/RQ28cdAl1tse9/isLeH9yqIEuzFWAHEX5OmpcrW7qcv
                     SWLFSofuUkHE2GuN8f4ipAzQ0Fn9Y2C463Q5DCzolhRmJrfXVgM6XLRnHg==
                     -----END CERTIFICATE-----
                   EOT
  }
}

data "ciphertrust_aws_custom_keystore" "cloudhsm_custom_keystore_data_source" {
  depends_on = [
    ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore,
  ]
  id = ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore.id
}

# Set connect_disconnect_keystore = CONNECT_KEYSTORE to connect above keystore
# Connect operation can take upto 30 minutes in AWS
# Disconnect operation can take upto 10 minutes in AWS

# Create an cloudhsm key in cloudhsm keystore
resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_1" {
  depends_on = [
    ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
  ]

  custom_key_store_id = ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore.id
  description = "desc for cloudhsm_key_1"
  enable_key = false
  alias = ["a6_cloudhsm_key_1"]
  tags = {
    Tagkey34 = "TagValue34"
    Tagkey44 = "TagValue44"
  }
  schedule_for_deletion_days = 7
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

output "cloudhsm_key_1" {
  value = ciphertrust_aws_cloudhsm_key.cloudhsm_key_1
}

data "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_1_data" {
  depends_on = [
    ciphertrust_aws_cloudhsm_key.cloudhsm_key_1,
  ]
  arn = ciphertrust_aws_cloudhsm_key.cloudhsm_key_1.arn
}

# Modify description, tag, alias, enable/disable key, etc, using respective fields
# CloudHSM key store can be deleted only after deleting keys in it.
# CloudHSM key in AWS can be scheduled to be deleted between 7-30 days.
