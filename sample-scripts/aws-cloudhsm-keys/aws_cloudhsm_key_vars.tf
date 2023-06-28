
variable "access_key_id" {
  type    = string
  default = "access-key-id"
}

variable "secret_access_key" {
  type    = string
  default = "secret-access-key"
}

variable "cks_linked" {
  type    = bool
  default = true
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

variable "cks_aws_xks_custom_keystore_type" {
  type    = string
  default = "AWS_CLOUDHSM"
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

variable "cks_aws_cloudhsm_keystore_hsm_cluster_id" {
  type    = string
  default = "cluster-id"
}

variable "cks_aws_cloudhsm_keystore_password" {
  type    = string
  default = "password"
}

