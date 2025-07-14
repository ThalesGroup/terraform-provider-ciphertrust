# Define an AWS connection
resource "ciphertrust_aws_connection" "aws-connection" {
  name = "aws_connection_name"
}

# Get the AWS account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws-connection.id
}

# Define a kms
resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws-connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}

# Define an AES CipherTrust key for creating EXTERNAL_KEY_STORE with CM as key source
# key should be unexportable, undeletable, symmetric AES 256 key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name                         = "aes-key-name"
  algorithm                    = "AES"
  usage_mask                   = 60
  unexportable                 = true
  undeletable                  = true
  # Setting remove_from_state_on_destroy to true will allow the key to be deleted from terraform state on destroy however, it will remain in CipherTrust Manager.
  remove_from_state_on_destroy = true
}

# Define unlinked external custom keystore with CipherTrust Manager as key source and PUBLIC_ENDPOINT proxy connectivity
resource "ciphertrust_aws_custom_keystore" "external_custom_keystor" {
  name                        = "keystore-name"
  region                      = ciphertrust_aws_kms.kms.regions[0]
  kms                         = ciphertrust_aws_kms.kms.name
  linked_state                = false
  connect_disconnect_keystore = "CONNECT_KEYSTORE"
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

# Define an unlinked cloudhsm custom keystore
resource "ciphertrust_aws_custom_keystore" "cloudhsm_keystore" {
  connect_disconnect_keystore = "CONNECT_KEYSTORE"
  name                        = "keystore-name"
  region                      = ciphertrust_aws_kms.kms.regions[0]
  kms                         = ciphertrust_aws_kms.kms.name
  linked_state                = false
  enable_success_audit_event  = true
  local_hosted_params {
    blocked         = false
    max_credentials = 8
  }
  aws_param {
    cloud_hsm_cluster_id     = "cluster-qxq7s6inshi"
    custom_key_store_type    = "AWS_CLOUDHSM"
    key_store_password       = "kmsuser-password"
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

# An example resource for importing an existing external custom key store
resource "ciphertrust_aws_custom_keystore" "imported_external_custom_keystore" {
  aws_param {
    custom_key_store_type  = "EXTERNAL_KEY_STORE"
    xks_proxy_connectivity = "PUBLIC_ENDPOINT"
    xks_proxy_uri_endpoint = "https://demo-xksproxy.thalescpl.io"
  }
  kms = "e5a912a6-53b3-436d-a9d9-1fb3a3c86f36"
  local_hosted_params {
    health_check_key_id = "b9698199e923444d88a5436064dcde9134c5b0de06bf4975989430a2fab3ce60"
    max_credentials     = 8
  }
  name   = "keystore-name"
  region = "ap-northeast-1"
}
