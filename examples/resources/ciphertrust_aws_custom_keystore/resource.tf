# Define an AWS connection
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "name"
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

# Define a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Define an AES CipherTrust key for use as the XKS health check key.
# The key must be unexportable, undeletable, and symmetric AES 256.
resource "ciphertrust_cm_key" "healthcheck_key" {
  name         = "name"
  algorithm    = "AES"
  usage_mask   = 60
  unexportable = true
  undeletable  = true
  # Setting remove_from_state_on_destroy to true allows the key to be removed
  # from Terraform state on destroy but it will remain in CipherTrust Manager.
  remove_from_state_on_destroy = true
}

# Define an unlinked XKS custom keystore with CipherTrust Manager as key source
# and PUBLIC_ENDPOINT proxy connectivity.
# linked_state defaults to false so the keystore is created in CCKM only and not
# registered in AWS KMS. To link the keystore, set linked_state = true at creation
# or via update after creation.
resource "ciphertrust_aws_custom_keystore" "external_keystore" {
  name   = "name"
  region = ciphertrust_aws_kms.kms.regions[0]
  kms_id = ciphertrust_aws_kms.kms.id
  local_hosted_params = {
    health_check_key_id = ciphertrust_cm_key.healthcheck_key.id
    max_credentials     = 2
    source_key_tier     = "local"
  }
  aws_param = {
    xks_proxy_uri_endpoint = "https://demo-xksproxy.thalescpl.io"
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type  = "EXTERNAL_KEY_STORE"
  }
}

# Define a scheduler job for XKS credential rotation.
# Only valid to add to linked key stores; reference in update config only.
resource "ciphertrust_scheduler" "credential_rotation" {
  name      = "name"
  operation = "CKSRotateCredentials"
  run_at    = "0 0 * * 0"
  run_on    = ""
}

# Use an update to link and connect the keystore above.
# Once linked a rotation scheduler can also be applied.
resource "ciphertrust_aws_custom_keystore" "external_keystore" {
  name                        = "name"
  region                      = ciphertrust_aws_kms.kms.regions[0]
  kms_id                      = ciphertrust_aws_kms.kms.id
  linked_state                = true
  connect_disconnect_keystore = "CONNECT_KEYSTORE"
  local_hosted_params = {
    health_check_key_id = ciphertrust_cm_key.healthcheck_key.id
    max_credentials     = 2
    source_key_tier     = "local"
  }
  aws_param = {
    xks_proxy_uri_endpoint = "https://demo-xksproxy.thalescpl.io"
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    custom_key_store_type  = "EXTERNAL_KEY_STORE"
  }
  enable_credential_rotation = {
    job_config_id = ciphertrust_scheduler.credential_rotation.id
  }
}

# Define a CloudHSM custom keystore. CloudHSM key stores are always linked by AWS.
# Do not set linked_state = false for AWS_CLOUDHSM keystores.
# To connect the keystore after creation, set connect_disconnect_keystore = "CONNECT_KEYSTORE"
# via update.
resource "ciphertrust_aws_custom_keystore" "cloudhsm_keystore" {
  name   = "name"
  region = ciphertrust_aws_kms.kms.regions[0]
  kms_id = ciphertrust_aws_kms.kms.id
  aws_param = {
    cloud_hsm_cluster_id     = "cluster-qxq7s6inshi"
    custom_key_store_type    = "AWS_CLOUDHSM"
    key_store_password       = "keystore-password"
    trust_anchor_certificate = <<-EOT
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
