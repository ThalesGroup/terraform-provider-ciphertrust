variable "hsm_certificate" {
  type    = string
  default = "/home/nvora/src/gitlab.protectv.local/ncryptify/debugging/lunaconfig/bal_aws_cm_vpc_par1.pem"
}

variable "hsm_hostname" {
  type    = string
  default = "65.151.32.249"
}

variable "hsm_partition_password" {
  type    = string
  default = "hsmso123"
}

variable "hsm_partition_label" {
  type    = string
#  default = "aws_cm_vpc_par1"
#  default = "aws_xks_nv_par1"
  default = "aws_xks_teamcity_tests_par1"
}

variable "hsm_partition_serial_number" {
  type    = string
  default = "1510716691531"
}

variable "access_key_id" {
  type    = string
  default = "AKIAYDIWP52TYST7Y4QS"
}

variable "secret_access_key" {
  type    = string
  default = "r56tlHK0XCoviiHeBzd8HXvg3Wg4592eXASCkKSt"
}

variable "cks_name" {
  type    = string
  default = "unlinked-xks-demo-6"
}

variable "cks_region" {
  type    = string
  default = "us-west-1"
}

variable "cks_blocked" {
  type    = bool
  default = false
}

variable "cks_linked" {
  type    = bool
  default = false
}

variable "cks_version_count" {
  type    = number
  default = 10
}

variable "cks_max_credentials_count" {
  type    = number
  default = 8
}

variable "cks_aws_xks_uri_endpoint" {
  type    = string
  default = "https://dev33-xksproxy.thalescpl.io"
}

variable "cks_aws_xks_proxy_connectivity" {
  type    = string
  default = "PUBLIC_ENDPOINT"
}

variable "cks_aws_xks_custom_keystore_type" {
  type    = string
  default = "EXTERNAL_KEY_STORE"
#  default = "AWS_CLOUDHSM"
}

variable "cks_aws_xks_custom_keystore_source_key_tier" {
  type    = string
  default = "hsm-luna"
}

variable "cks_aws_cks_health_check_key_id" {
  type    = string
  default = "efbc9e23-d269-447d-bd37-65d8b3973852"
}

variable "cks_aws_cks_vpc_endpoint_service_name" {
  type    = string
  default = "vpc-endpoint-name-n1"
}

variable "virtual_key_deletable" {
  type    = bool
  default = true
}

variable "cks_aws_cks_connect_disconnect_state" {
  type    = string
  default = "DISCONNECT_KEYSTORE"
}

variable "cks_aws_cloudhsm_keystore_hsm_cluster_id" {
  type    = string
  default = "cluster-txljbyeoqoi"
}

variable "cks_aws_cloudhsm_keystore_password" {
  type    = string
  default = "password"
}

variable "cks_aws_cloudhsm_trust_anchor_certificate_path"{
  type    = string
  default = "/home/nvora/cloudhsm_cert.pem"
}

# XKS key Policy variables
variable "admin" {
  type    = string
  default = "ashishadval"
}

variable "admin_role" {
  type    = string
  default = "ADFS"
}

variable "user" {
  type    = string
  default = "ashishadval"
}

variable "user_role" {
  type    = string
  default = "ADFS"
}

variable "xks_key_blocked" {
  type    = bool
  default = false
}

variable "xks_key_linked" {
  type    = bool
  default = false
}
