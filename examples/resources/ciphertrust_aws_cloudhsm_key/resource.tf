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

## Create cloudHSM keystore
resource "ciphertrust_aws_custom_keystore" "cloudhsm_custom_keystore" {
  depends_on = [
    ciphertrust_aws_kms.kms,
  ]
  name         = "cloudhsm-keystore-demo-1"
  region       = "us-west-1"
  kms          = ciphertrust_aws_kms.kms.name
  connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
  aws_param {
    custom_key_store_type       = "AWS_CLOUDHSM"
    cloud_hsm_cluster_id        = "cluster-pxkcyeoqij"
    key_store_password          = "keystore-password"
    trust_anchor_certificate    = <<-EOT
	                 -----BEGIN CERTIFICATE-----
	                 MIIDhzCCAm+gAwIBAgIUHdJu4algAFs22h87meBhd9Qe4eMoDQYJKoZIhvcNAQEL
	                 BQAwUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRAwDgYQVQQHDAdTYW5Kb3Nl
	                 MQ8wDQYDVQQKDAZUaGFsZXMxFDASBgNVBAsMC0VuZ2luZWVyaW5nMB4XDTIyMDYy
	                 MzA2NTgwOFoXDTMyMDYyMjA2NTgwOFowUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgM
	                 AkNBMRAwDgYDVQQHDAdTYW5Kb3NlMQ8wDQYDVQQKDAZUaEFsZXMxFDASBgNVBAsM
	                 C0VtZ2lvZWVyaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvi0o
	                 wtYFziFkbhtH0X0+0fhvcGLJ4SYTOU50ZGa7GlfsKC4i5vGxXFEJ1QwJ+WmkyXwo
	                 RCWaXQbFkFIxlDDIgOe64Z8FRiqdRGXPAYXvJC5pM015kOGtuMrT759Ifbux81Ng
	                 ULlUbz7uLGxut+IbLXIG+/lkDI8OtYNLtU5hbTG/QrTieFg7ZQ/IKKbmCKB3m3cv
	                 l0MzSMZQXMgNmsbb9SASTgSgaBdAF99sp3B78jHFDqikZHvrxjPBRqi/OsSBefmV
	                 LymMhPBVcF9FWJgL+YpxDjKP4ieo8rqWK9xEDnu6VmVx0guQ40uM4ycaDljBueW6
	                 J9FqXFp63FGrGKu2vwIDBQABo1MwUTAdBgMVHQ4EFgQUi/RAIOrEPaUm9T6P+Ju3
	                 qTKpf90wHwYDVR0jBBgwFoAUi/RAIOrEPaUm9T6P+Ju3qTKpf90wDwYDVR0TAQH/
	                 BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAfhC8EghStmPq770Edt6lfoEC6pIO
	                 UCMoiwnX9KL7WdKPx7auyJmxj3+MbYqMSzilXPA57J1WE6BhT3JOT4nPsO/IpFv2
	                 fbpUVW9ypwrRQE1S1v6BjvQd5J49c3ZDfH634jCwGwxcBY2gSbZorLb03aH7R2uF
	                 31jlyotNaUd3eWjo11jwVt9ZhpcxbaiK98Q6UcUro0Ok2BaQdZZthnuMMnwK8iO2
	                 w3XiEJU3uaUbs1jC6x2Q/RQ28cdAl1tse9/isLeH9yqIEuzFWBHEX5OmpcrW7qcv
	                 SWLFSofuUkHD1GuN8f4ipAzQ0Fn9Y2C463Q3DCzolhRmJrfXVgM6XLRnHg==
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

# Create an cloudhsm key in cloudhsm keystore
resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_1" {
  depends_on = [
    ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
  ]

  custom_key_store_id = ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore.id
  description = "desc for cloudhsm_key_1"
  enable_key = false
  alias = ["a5_cloudhsm_key_1"]
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
  arn = "arn:aws:kms:us-west-1:556782317223:key/991fc126-1281-4300-a174-5b39d4e78cb0"
}
