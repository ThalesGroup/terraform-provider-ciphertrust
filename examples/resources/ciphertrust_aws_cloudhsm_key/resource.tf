# Define an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = "name"
}

# Define a kms
resource "ciphertrust_aws_kms" "kms" {
  depends_on = [
    ciphertrust_aws_connection.aws-connection,
  ]
  account_id     = "account-id"
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = "name"
  regions        = ["region"]
}

# Define a CloudHSM custom keystore
resource "ciphertrust_aws_custom_keystore" "cloudhsm_keystore" {
  depends_on = [
    ciphertrust_aws_kms.kms,
  ]
  name                        = "name"
  region                      = "region"
  kms_id                      = ciphertrust_aws_kms.kms.id
  aws_param = {
    custom_key_store_type    = "AWS_CLOUDHSM"
    cloud_hsm_cluster_id     = "cluster-id"
    key_store_password       = "keystore-password"
    trust_anchor_certificate = <<-EOT
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

# Define a policy template using key users and roles
resource "ciphertrust_aws_policy_template" "policy_template" {
  name             = "name"
  kms_id           = ciphertrust_aws_kms.kms.id
  key_admins       = ["key-admins"]
  key_admins_roles = ["key-admins-roles"]
  key_users        = ["key-users"]
  key_users_roles  = ["key-users-roles"]
}

# Define a CloudHSM key in the CloudHSM keystore
resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key" {
  custom_key_store_id = ciphertrust_aws_custom_keystore.cloudhsm_keystore.id
  aws_param = {
    alias       = ["alias"]
    description = "description"
  }
  key_policy = {
    policy_template = ciphertrust_aws_policy_template.policy_template.id
  }
}
