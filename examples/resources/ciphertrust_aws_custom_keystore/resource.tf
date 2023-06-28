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

# Create Luna Connection, Luna HSM server, Luna Symmetric key for Luna as key source
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

# Create linked external custom keystore with luna as key source; with xks proxy connectivity as PUBLIC_ENDPOINT
resource "ciphertrust_aws_custom_keystore" "linked_xks_custom_keystore_for_luna_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
    ciphertrust_hsm_partition.hsm_partition,
    ciphertrust_hsm_key.hsm_aes_key,
  ]
  name = "linked-xks-demo-1-for-luna-as-source"
  region = "us-west-1"
  kms    = ciphertrust_aws_kms.kms.name
  linked_state = true
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

output "linked_xks_custom_keystore_for_luna_as_source" {
  value = ciphertrust_aws_custom_keystore.linked_xks_custom_keystore_for_luna_as_source
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

output "cloudhsm_custom_keystore" {
  value = data.ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore_data_source
}