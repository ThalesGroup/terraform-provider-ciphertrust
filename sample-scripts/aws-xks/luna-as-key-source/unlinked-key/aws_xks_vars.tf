variable "hsm_certificate" {
  type    = string
  default = "/path/to/hsm/servert_certificate.pem"
}

variable "hsm_hostname" {
  type    = string
  default = "5.21.132.149"
}

variable "hsm_partition_password" {
  type    = string
  default = "password"
}

variable "hsm_partition_label" {
  type    = string
  default = "partition_label"
}

variable "hsm_partition_serial_number" {
  type    = string
  default = "1510716691531"
}

variable "access_key_id" {
  type    = string
  default = "access-key-id"
}

variable "secret_access_key" {
  type    = string
  default = "secret-access-key"
}

variable "cks_name" {
  type    = string
  default = "unlinked-xks-demo-1-for-luna-as-source"
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

variable "cks_max_credentials_count" {
  type    = number
  default = 8
}

variable "cks_aws_xks_uri_endpoint" {
  type    = string
  default = "https://test-xksproxy.thalescpl.io"
}

variable "cks_aws_xks_proxy_connectivity" {
  type    = string
  default = "PUBLIC_ENDPOINT"
}

variable "cks_aws_xks_custom_keystore_type" {
  type    = string
  default = "EXTERNAL_KEY_STORE"
}

variable "cks_aws_xks_source_key_tier" {
  type    = string
  default = "hsm-luna"
}

variable "virtual_key_deletable" {
  type    = bool
  default = false
}

variable "cks_aws_cks_connect_disconnect_state" {
  type    = string
  default = "DISCONNECT_KEYSTORE"
}

# XKS key Policy variables
variable "admin" {
  type    = string
  default = "aws-iam-user"
}

variable "admin_role" {
  type    = string
  default = "aws-iam-role"
}

variable "user" {
  type    = string
  default = "aws-iam-user"
}

variable "user_role" {
  type    = string
  default = "aws-iam-role"
}

variable "xks_key_blocked" {
  type    = bool
  default = false
}

variable "xks_key_linked" {
  type    = bool
  default = false
}
