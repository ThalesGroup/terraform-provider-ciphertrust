
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
  default = "unlinked-xks-demo-6"
}

variable "cks_region" {
  type    = string
  default = "us-west-2"
}

variable "cks_blocked" {
  type    = bool
  default = false
}

variable "cks_linked" {
  type    = bool
  default = true
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
  default = "local"
}

variable "cm_key_undeletable" {
  type    = bool
  default = true
}

variable "cks_aws_cks_connect_disconnect_state" {
  type    = string
  default = "DISCONNECT_KEYSTORE"
}

# XKS key Policy variables
variable "admin" {
  type    = string
  default = "aws-iam-user1"
}

variable "admin_role" {
  type    = string
  default = "aws-iam-role1"
}

variable "user" {
  type    = string
  default = "aws-iam-user2"
}

variable "user_role" {
  type    = string
  default = "aws-iam-role2"
}

variable "xks_key_blocked" {
  type    = bool
  default = false
}

variable "xks_key_linked" {
  type    = bool
  default = true
}
