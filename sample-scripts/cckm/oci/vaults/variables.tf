variable "oci_key_file" {
  description = "Path to or contents of the OCI private key file."
  type        = string
}

variable "oci_pub_key_fingerprint" {
  description = "OCI public key fingerprint."
  type        = string
}

variable "oci_region" {
  description = "OCI region."
  type        = string
}

variable "oci_tenancy_ocid" {
  description = "OCI tenancy OCID."
  type        = string
}

variable "oci_user_ocid" {
  description = "OCI user OCID."
  type        = string
}
