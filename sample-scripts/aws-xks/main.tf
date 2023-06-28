#terraform {
#  required_providers {
#    ciphertrust = {
#      source  = "ThalesGroup/ciphertrust"
#      version = "0.9.0-beta8"
#    }
#  }
#}

terraform {
  required_providers {
    ciphertrust = {
      version = ">= 1.0.0"
      source  = "thales.com/terraform/ciphertrust"
    }
  }
  required_version = ">= 0.12.26"
}

provider "ciphertrust" {
  address = "https://dev33-xksproxy.thalescpl.io"
#  address = "https://52.86.120.81"
  username = "admin"
  password = "KeySecure_2"
  domain = "root"
  log_level = "debug"
}

resource "random_id" "random" {
  byte_length = 8
}

locals {
  luna_hsm_connection_name = "luna-hsm-connection-${lower(random_id.random.hex)}"
  aws_connection_name = "aws-connection-${lower(random_id.random.hex)}"
  kms_name        = "kms-${lower(random_id.random.hex)}"
  min_key_name    = "aes-min-params-${lower(random_id.random.hex)}"
  max_key_name    = "aes-max-params-${lower(random_id.random.hex)}"
#  cks_name = "cks-${lower(random_id.random.hex)}"
#  template_with_users_and_roles = "template-with-users-and-roles-${lower(random_id.random.hex)}"
  template_with_users_and_roles = "template-with-users-and-roles-test"
}

# Create a hsm network server
#resource "ciphertrust_hsm_server" "hsm_server" {
#  hostname        = var.hsm_hostname
#  hsm_certificate = var.hsm_certificate
#}

# Add create a hsm connection
# is_ha_enabled must be true for more than one partition
#resource "ciphertrust_hsm_connection" "hsm_connection" {
#  depends_on = [
#    ciphertrust_hsm_server.hsm_server,
#  ]
#  hostname  = var.hsm_hostname
#  server_id = ciphertrust_hsm_server.hsm_server.id
#  name      = local.luna_hsm_connection_name
#  partitions {
#    partition_label = var.hsm_partition_label
#    serial_number   = var.hsm_partition_serial_number
#  }
#  partition_password = var.hsm_partition_password
#  is_ha_enabled      = false
#}
#output "hsm_connection_id" {
#  value = ciphertrust_hsm_connection.hsm_connection.id
#}

# Add a partition to connection
#resource "ciphertrust_hsm_partition" "hsm_partition" {
#  depends_on = [
#    ciphertrust_hsm_connection.hsm_connection,
#  ]
#  hsm_connection = ciphertrust_hsm_connection.hsm_connection.id
#}
#output "hsm_partition" {
#  value = ciphertrust_hsm_partition.hsm_partition
#}

# Create a Luna-HSM symmetric key
#resource "ciphertrust_hsm_key" "hsm_aes_key" {
#  depends_on = [
#    ciphertrust_hsm_partition.hsm_partition,
#  ]
#  attributes = ["CKA_SENSITIVE", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP", "CKA_UNWRAP"]
#  label        = "key-name-${lower(random_id.random.hex)}"
#  mechanism    = "CKM_AES_KEY_GEN"
#  partition_id = ciphertrust_hsm_partition.hsm_partition.id
#  key_size     = 256
#}
#
#output "hsm_aes_key" {
#  value = ciphertrust_hsm_key.hsm_aes_key
#}

# Create a virtual key from luna
#resource "ciphertrust_virtual_key" "virtual_key_from_luna_key" {
#  depends_on = [
#    ciphertrust_hsm_key.hsm_aes_key,
#  ]
#  deletable = var.virtual_key_deletable
#  source_key_id = ciphertrust_hsm_key.hsm_aes_key.id
#  source_key_tier = "hsm-luna"
#}
#output "virtual_key_from_luna_key" {
#  value = ciphertrust_virtual_key.virtual_key_from_luna_key
#}
#
#data "ciphertrust_virtual_key" "virtual_key_from_luna_key_data" {
#  depends_on = [
#    ciphertrust_virtual_key.virtual_key_from_luna_key,
#  ]
#  id = ciphertrust_virtual_key.virtual_key_from_luna_key.id
#}
#output "data_virtual_key_from_luna_key_data" {
#  value = data.ciphertrust_virtual_key.virtual_key_from_luna_key_data
#}

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
#  regions        = data.ciphertrust_aws_account_details.account_details.regions
  regions        = ["us-west-1"]
}

## Create cloudHSM keystore - test
#resource "ciphertrust_aws_custom_keystore" "cloudhsm_custom_keystore" {
#  depends_on = [
#    ciphertrust_aws_kms.kms,
##    ciphertrust_hsm_partition.hsm_partition,
##    ciphertrust_hsm_key.hsm_aes_key,
#  ]
##  name         = var.cks_name
#  name         = "cloudhsm-keystore-demo-1"
#  region       = var.cks_region
#  kms          = ciphertrust_aws_kms.kms.name
##  linked_state = var.cks_linked
#  linked_state = true
##  connect_disconnect_keystore = var.cks_aws_cks_connect_disconnect_state
#  connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
#  #  version_count = var.cks_version_count
##  local_hosted_params {
##    blocked      = var.cks_blocked // not applicable to cloudhsm keystore
##    blocked = false
##  }
#  aws_param {
##    custom_key_store_type       = var.cks_aws_xks_custom_keystore_type
#    custom_key_store_type       = "AWS_CLOUDHSM"
#    cloud_hsm_cluster_id        = var.cks_aws_cloudhsm_keystore_hsm_cluster_id
#    key_store_password          = var.cks_aws_cloudhsm_keystore_password
##    trust_anchor_certificate    = var.cks_aws_cloudhsm_trust_anchor_certificate_path
#    trust_anchor_certificate    = <<-EOT
#	                 -----BEGIN CERTIFICATE-----
#	                 MIIDhzCCAm+gAwIBAgIUHdJu4algAFs22h87meBhd9Qe4rMwDQYJKoZIhvcNAQEL
#	                 BQAwUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRAwDgYDVQQHDAdTYW5Kb3Nl
#	                 MQ8wDQYDVQQKDAZUaGFsZXMxFDASBgNVBAsMC0VuZ2luZWVyaW5nMB4XDTIyMDYy
#	                 MzA2NTgwOFoXDTMyMDYyMjA2NTgwOFowUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgM
#	                 AkNBMRAwDgYDVQQHDAdTYW5Kb3NlMQ8wDQYDVQQKDAZUaGFsZXMxFDASBgNVBAsM
#	                 C0VuZ2luZWVyaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvi0o
#	                 wtYFziFlbhtH0X0+0fhvcGLJ4SYTOU50ZGb7GlfsKC4i5vGxXFEJ1QwJ+WmkyXwo
#	                 RCWaXQbFkFIxlDDIgOe64Z8FRiqdRGXPAYWvJC5pM015kOGtuMrT759Ifbux81Ng
#	                 ULlUbz7uLGxut+IbLXIG+/lkDI8OtYNLtU4hbTG/QrTieFg7ZQ/IKKbmCKB3m3cv
#	                 l0MzSMZQXMgNmsbb9SATTgSgaBdAF99sp3B78jHFDqikZHvrxjPBRqi/OsSBefmV
#	                 LymMhPBVdF9FWJgL+YpxDjKP4ieo8rqWK9zEDnu6VmVx0guQ40uM4ycaDljBueW6
#	                 J9FqXFp62FGrGKu2vwIDAQABo1MwUTAdBgNVHQ4EFgQUi/RAIOrEPaUm9T6P+Ju3
#	                 qTKpf90wHwYDVR0jBBgwFoAUi/RAIOrEPaUm9T6P+Ju3qTKpf90wDwYDVR0TAQH/
#	                 BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAfhC8EghStmPq770Edt6lfoEC6pIO
#	                 UCMoiwnX9KL7WdKPx7auyJmxj3+MbYqMSzilXPA57J1WE6BhT3JOT4nPsO/IpFv2
#	                 fbpUVW9ypwrRQE1S1v6BjvQd5J49c3ZDfH634jCwGwxcBY2gSbZorLb03aH7R2uF
#	                 31jlyotNaUd3eWjo11jwVt9ZhpcxbaiK98Q6UcUro0Ok2BaQdZZthnuMMnwK8iO2
#	                 w3XiEJU3ubUbs1jC6x2Q/RQ28cdAl1tse9/isLeH9yqIEuzFWAHEX5OmpcrW7qcv
#	                 SWLFSofuUkHE1GuN8f4ipAzQ0Fn9Y2C463Q3DCzolhRmJrfXVgM6XLRnHg==
#	                 -----END CERTIFICATE-----
#	               EOT
#  }
#}
#
#data "ciphertrust_aws_custom_keystore" "cloudhsm_custom_keystore_data_source" {
#  depends_on = [
#    ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore,
#  ]
#  id = ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore.id
#}
#
#output "cloudhsm_custom_keystore" {
#  value = data.ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore_data_source
#}
#


#output "cloudhsm_custom_keystore" {
#  value = ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore
#}
#
## Create an cloudhsm key in cloudhsm keystore
#resource "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_1" {
#  depends_on = [
#    ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore,
#    ciphertrust_aws_policy_template.template_with_users_and_roles,
#  ]
#
#  custom_key_store_id = ciphertrust_aws_custom_keystore.cloudhsm_custom_keystore.id
##  aws_param {
#  description = "desc for cloudhsm_key_5"
#  enable_key = false
#  alias = ["a58_cloudhsm_key_5"]
#  tags = {
#    Tagkey34 = "TagValue34"
#    Tagkey44 = "TagValue44"
#  }
#  #    }
#  #  auto_rotate = true
#  schedule_for_deletion_days = 7
#  key_policy {
#    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
#  }
#}
#
#output "cloudhsm_key_1" {
#  value = ciphertrust_aws_cloudhsm_key.cloudhsm_key_1
#}
#
#data "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_1_data" {
#  depends_on = [
#    ciphertrust_aws_cloudhsm_key.cloudhsm_key_1,
#  ]
#  #  arn = ciphertrust_aws_key.aes_native_symm_1.arn
#  arn = "arn:aws:kms:us-west-1:556782317223:key/991fc126-1281-4300-a174-5b39d4e78cb0"
#}
#output "data_source_cloudhsm_key_1_data" {
#  value = data.ciphertrust_aws_cloudhsm_key.cloudhsm_key_1_data
#}

# Create unlinked external custom keystore
#resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore" {
#  depends_on = [
#    ciphertrust_aws_kms.kms,
#    ciphertrust_hsm_partition.hsm_partition,
#    ciphertrust_hsm_key.hsm_aes_key,
#  ]
#  name = var.cks_name
#  region = var.cks_region
#  kms    = ciphertrust_aws_kms.kms.name
#  linked_state = var.cks_linked
#  connect_disconnect_keystore = var.cks_aws_cks_connect_disconnect_state
#  #  version_count = var.cks_version_count
#    local_hosted_params {
#      partition_id = ciphertrust_hsm_partition.hsm_partition.id
#      blocked = var.cks_blocked
#      health_check_key_id = ciphertrust_hsm_key.hsm_aes_key.id
#      #health_check_key_id = var.cks_aws_cks_health_check_key_id
#      max_credentials = var.cks_max_credentials_count
#      source_key_tier = var.cks_aws_xks_custom_keystore_source_key_tier
#    }
#    aws_param {
#      xks_proxy_uri_endpoint = var.cks_aws_xks_uri_endpoint
#      xks_proxy_connectivity = var.cks_aws_xks_proxy_connectivity
#      custom_key_store_type = var.cks_aws_xks_custom_keystore_type
#      #xks_proxy_vpc_endpoint_service_name = var.cks_aws_cks_vpc_endpoint_service_name
#    }
#}
#
#output "unlinked_xks_custom_keystore" {
#  value = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore
#}
#
#data "ciphertrust_aws_custom_keystore" "data_unlinked_xks_custom_keystore_data" {
#  depends_on = [
#    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore,
#  ]
#  id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
#}
#output "data_unlinked_xks_custom_keystore_data" {
#  value = data.ciphertrust_aws_custom_keystore.data_unlinked_xks_custom_keystore_data
#}
#
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

# Create an XKS key with luna as key source
#resource "ciphertrust_aws_linked_xks_key" "xks_key_with_luna_as_source" {
#  depends_on = [
##    ciphertrust_aws_kms.kms,
##    ciphertrust_hsm_partition.hsm_partition,
##    ciphertrust_hsm_key.hsm_aes_key,
#    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore,
#    ciphertrust_virtual_key.virtual_key_from_luna_key,
#    ciphertrust_aws_policy_template.template_with_users_and_roles,
#  ]
#
#  local_hosted_params {
#      blocked = var.xks_key_blocked
#      custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
##     linked = var.cks_linked
#      source_key_id = ciphertrust_virtual_key.virtual_key_from_luna_key.id
#      source_key_tier = var.cks_aws_xks_custom_keystore_source_key_tier
#  }
##  aws_param {
#    description = "desc for xks 4 luna based key - modified3"
#    enable_key = false
#    alias = ["a47"]
#    tags = {
#      Tagkey1 = "TagValue1"
#      Tagkey2 = "TagValue2"
#    }
##  }
#  key_policy {
#    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
#  }
#}
#
#output "xks_key_with_luna_as_source" {
#  value = ciphertrust_aws_linked_xks_key.xks_key_with_luna_as_source
#}

# Create an XKS key with luna as key source
#resource "ciphertrust_aws_unlinked_xks_key" "xks_unlinked_key_with_luna_as_source" {
#  depends_on = [
#    #    ciphertrust_aws_kms.kms,
#    #    ciphertrust_hsm_partition.hsm_partition,
#    #    ciphertrust_hsm_key.hsm_aes_key,
#    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore,
#    ciphertrust_virtual_key.virtual_key_from_luna_key,
#    ciphertrust_aws_policy_template.template_with_users_and_roles,
#  ]
#
#  local_hosted_params {
##    blocked = var.xks_key_blocked
#    blocked = false
#    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
##    linked = var.xks_key_linked
##    linked = false
#    source_key_id = ciphertrust_virtual_key.virtual_key_from_luna_key.id
#    source_key_tier = var.cks_aws_xks_custom_keystore_source_key_tier
#  }
#  #  aws_param {
#  description = "desc for xks 4 luna based unlinked to linked key"
#  enable_key = true
##  alias = ["a49_luna_unlinked_key"]
##  tags = {
##    Tagkey7 = "TagValue7"
##    Tagkey8 = "TagValue8"
##  }
#  #  }
#  key_policy {
#    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
#  }
#}

#output "xks_unlinked_key_with_luna_as_source" {
#  value = ciphertrust_aws_unlinked_xks_key.xks_unlinked_key_with_luna_as_source
#}

## Create an XKS key with luna as key source
#resource "ciphertrust_aws_xks_key" "xks_unlinked_key_with_luna_as_source_1" {
#  depends_on = [
#    #    ciphertrust_aws_kms.kms,
#    #    ciphertrust_hsm_partition.hsm_partition,
#    #    ciphertrust_hsm_key.hsm_aes_key,
#    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore,
#    ciphertrust_virtual_key.virtual_key_from_luna_key,
#    ciphertrust_aws_policy_template.template_with_users_and_roles,
#  ]
#
#  local_hosted_params {
#    #    blocked = var.xks_key_blocked
#    blocked = false
#    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore.id
#    #    linked = var.xks_key_linked
#    linked = false
#    source_key_id = ciphertrust_virtual_key.virtual_key_from_luna_key.id
#    source_key_tier = var.cks_aws_xks_custom_keystore_source_key_tier
#  }
#  #  aws_param {
#  description = "desc for xks_unlinked_key_with_luna_as_source_1 modified after linking"
#  enable_key = true
#    alias = ["a51_luna_unlinked_key_1"]
##    tags = {
##      Tagkey1 = "TagValue1"
##      Tagkey2 = "TagValue2"
##    }
##    }
##  auto_rotate = true
#  key_policy {
#    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
#  }
#}
#
#output "xks_unlinked_key_with_luna_as_source_1" {
#  value = ciphertrust_aws_xks_key.xks_unlinked_key_with_luna_as_source_1
#}

# Create an AES CipherTrust key
resource "ciphertrust_cm_key" "cm_aes_key" {
  name      = local.min_key_name
  algorithm = "AES"
  usage_mask = 60
  unexportable = true
  undeletable = false
}
output "cm_aes_key" {
  value = ciphertrust_cm_key.cm_aes_key
}

# Create unlinked external custom keystore
resource "ciphertrust_aws_custom_keystore" "unlinked_xks_custom_keystore_for_cm_as_source" {
  depends_on = [
    ciphertrust_aws_kms.kms,
#    ciphertrust_hsm_partition.hsm_partition,
    ciphertrust_cm_key.cm_aes_key,
  ]
  name = "unlinked-xks-demo-7-for-cm-as-source"
  region = var.cks_region
  kms    = ciphertrust_aws_kms.kms.name
  linked_state = false
  connect_disconnect_keystore = "DISCONNECT_KEYSTORE"
  #  version_count = var.cks_version_count
  local_hosted_params {
    blocked = false
    health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
    #health_check_key_id = var.cks_aws_cks_health_check_key_id
    max_credentials = var.cks_max_credentials_count
    source_key_tier = "local"
  }
  aws_param {
    xks_proxy_uri_endpoint = var.cks_aws_xks_uri_endpoint
    xks_proxy_connectivity = var.cks_aws_xks_proxy_connectivity
    custom_key_store_type = var.cks_aws_xks_custom_keystore_type
    #xks_proxy_vpc_endpoint_service_name = var.cks_aws_cks_vpc_endpoint_service_name
  }
}

output "unlinked_xks_custom_keystore_for_cm_as_source" {
  value = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source
}


# Create an XKS key with cm as key source
resource "ciphertrust_aws_xks_key" "xks_unlinked_key_with_cm_as_source_2" {
  depends_on = [
    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source,
    ciphertrust_cm_key.cm_aes_key,
    ciphertrust_aws_policy_template.template_with_users_and_roles,
  ]

  local_hosted_params {
    #    blocked = var.xks_key_blocked
    blocked = false
    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source.id
    #    linked = var.xks_key_linked
    linked = false
    source_key_id = ciphertrust_cm_key.cm_aes_key.id
    source_key_tier = "local"
  }
  #  aws_param {
  description = "desc for xks_unlinked_key_with_cm_as_source_2"
#  enable_key = false
  alias = ["a52_luna_unlinked_key_1"]
#      tags = {
#        Tagkey1 = "TagValue1"
#        Tagkey2 = "TagValue2"
#      }
  #    }
  #  auto_rotate = true
  key_policy {
    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
  }
}

#output "xks_unlinked_key_with_cm_as_source_2" {
#  value = ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_2
#}
#
#resource "ciphertrust_aws_key" "aes_native_symm_1" {
#  description = "NSV 3"
#  kms                                = ciphertrust_aws_kms.kms.id
#  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
#  tags = {
#    TagKey = "TagValue"
#  }
#  key_policy {
#    policy_template = "0efb637d-6ce2-4b5c-8f90-ae0d20c7b4be" // invalid policy template to reproduce error condition
##    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
#  }
#  region                     = ciphertrust_aws_kms.kms.regions[0]
#  schedule_for_deletion_days = 7
#}
#output "sym_key_native_params" {
#  value = ciphertrust_aws_key.aes_native_symm_1.id
#}
#
#data "ciphertrust_aws_key" "aws_key_data_source" {
#  depends_on = [
#    ciphertrust_aws_key.aes_native_symm_1,
#  ]
##  arn = ciphertrust_aws_key.aes_native_symm_1.arn
#  arn = "arn:aws:kms:us-west-1:556782317223:key/8209471b-20bd-4751-a7c2-8d0f3c21ee18"
#}
#output "data_source_aws_key_native_params" {
#  value = data.ciphertrust_aws_key.aws_key_data_source
#}

# demo
# Create an XKS key with cm as key source
#resource "ciphertrust_aws_xks_key" "xks_unlinked_key_with_cm_as_source_3" {
#  depends_on = [
#    #    ciphertrust_aws_kms.kms,
#    #    ciphertrust_hsm_partition.hsm_partition,
#    #    ciphertrust_hsm_key.hsm_aes_key,
#    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source,
#    ciphertrust_cm_key.cm_aes_key,
#    ciphertrust_aws_policy_template.template_with_users_and_roles,
#  ]
#
#  local_hosted_params {
#    #    blocked = var.xks_key_blocked
#    blocked = false
#    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source.id
#    #    linked = var.xks_key_linked
#    linked = true
#    source_key_id = ciphertrust_cm_key.cm_aes_key.id
#    source_key_tier = "local"
#  }
#  #  aws_param {
#  description = "desc for xks_unlinked_key_with_cm_as_source_3"
#    enable_key = true
#  alias = ["a53_luna_unlinked_key_1"]
#  tags = {
#    Tagkey1 = "TagValue1"
#    Tagkey2 = "TagValue2"
#  }
#  #    }
#  #  auto_rotate = true
#  key_policy {
#    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
#  }
#}
#
#output "xks_unlinked_key_with_cm_as_source_3" {
#  value = ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_3
#}

#demo 2
# Create an XKS key with cm as key source
#resource "ciphertrust_aws_xks_key" "xks_linked_key_with_cm_as_source_5" {
#  depends_on = [
#    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source,
#    ciphertrust_cm_key.cm_aes_key,
#    ciphertrust_aws_policy_template.template_with_users_and_roles,
#  ]
#
#  local_hosted_params {
#    #    blocked = var.xks_key_blocked
#    blocked = false
#    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source.id
#    linked = true
#    source_key_id = ciphertrust_cm_key.cm_aes_key.id
#    source_key_tier = "local"
#  }
#  #  aws_param {
#  description = "desc for xks_linked_key_with_cm_as_source_5"
##  enable_key = false
#  alias = ["a55_luna_linked_key_1"]
#  tags = {
#    Tagkey1 = "TagValue1"
#    Tagkey2 = "TagValue2"
#  }
#  #    }
#  #  auto_rotate = true
#  key_policy {
#    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
#  }
#}
#
#output "xks_linked_key_with_cm_as_source_5" {
#  value = ciphertrust_aws_xks_key.xks_linked_key_with_cm_as_source_5
#}

# Create an XKS key with cm as key source
#resource "ciphertrust_aws_xks_key" "xks_unlinked_key_with_cm_as_source_3" {
#  depends_on = [
#    #    ciphertrust_aws_kms.kms,
#    #    ciphertrust_hsm_partition.hsm_partition,
#    #    ciphertrust_hsm_key.hsm_aes_key,
#    ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source,
#    ciphertrust_cm_key.cm_aes_key,
#    ciphertrust_aws_policy_template.template_with_users_and_roles,
#  ]
#
#  local_hosted_params {
#    #    blocked = var.xks_key_blocked
#    blocked = false
#    custom_key_store_id = ciphertrust_aws_custom_keystore.unlinked_xks_custom_keystore_for_cm_as_source.id
#    #    linked = var.xks_key_linked
#    linked = true
#    source_key_id = ciphertrust_cm_key.cm_aes_key.id
#    source_key_tier = "local"
#  }
#  #  aws_param {
#  description = "desc for xks_unlinked_key_with_cm_as_source_3 mod"
#  #  enable_key = false
#  alias = ["a52_luna_unlinked_key_3"]
#  tags = {
#    Tagkey33 = "TagValue33"
#    Tagkey44 = "TagValue44"
#  }
#  #    }
#  #  auto_rotate = true
#  key_policy {
#    policy_template = ciphertrust_aws_policy_template.template_with_users_and_roles.id
#  }
#}
#
#output "xks_unlinked_key_with_cm_as_source_3" {
#  value = ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_3
#}
#
#data "ciphertrust_aws_xks_key" "xks_unlinked_key_with_cm_as_source_3_data" {
#  depends_on = [
#    ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_3,
#  ]
#  #  arn = ciphertrust_aws_key.aes_native_symm_1.arn
#  arn = "arn:aws:kms:us-west-1:556782317223:key/ef4c1b19-2669-4c24-9ae1-d590ba5c660a"
#}
#output "data_xks_unlinked_key_with_cm_as_source_3_data" {
#  value = data.ciphertrust_aws_xks_key.xks_unlinked_key_with_cm_as_source_3_data
#}
