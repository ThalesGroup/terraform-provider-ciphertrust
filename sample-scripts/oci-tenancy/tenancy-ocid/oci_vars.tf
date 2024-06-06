variable "oci_key_file" {
  type    = string
  default = "oci-key-file"
}

variable "pub_key_fingerprint" {
  type    = string
  default = "oci-pubkey-fingerprint"
}

variable "region" {
  type    = string
  default = "oci-region"
}

variable "tenancy_ocid" {
  type    = string
  default = "tenancy-ocid"
}

variable "tenancy_name" {
  type    = string
  default = "tenancy-name"
}

variable "user_ocid" {
  type    = string
  default = "user-ocid"
}

variable "openid_config_url" {
  type    = string
  default = "openid-config-url"
}

variable "compartment_name" {
  type    = string
  default = "oci-compartment-name"
}

variable "client_application_id" {
  type    = string
  default = "oci-client-application-id"
}

variable "oci_key_policy" {
  type    = string
  default = "oci-key-policy"
}

variable "oci_key_policy_file" {
  type    = string
  default = "oci-key-policy-file"
}

variable "oci_vault_policy" {
  type    = string
  default = "oci-vault-policy"
}

variable "oci_vault_policy_file" {
  type    = string
  default = "oci-vault-policy-file"
}
