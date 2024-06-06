variable "oci_key_file" {
  type    = string
  default = "/server_certs/oci-key-file.pem"
}

variable "pub_key_fingerprint" {
  type    = string
  default = "84:b3:de:e8:89:d8:dd:ad:7f:b0:d6:a0:f9:c1:0a:0c"
}

variable "region" {
  type    = string
  default = "us-ashburn-1"
}

variable "tenancy_ocid" {
  type    = string
  default = "ocid1.tenancy.oc1..aaaaaaaadixb52q2mvlsn634ql5aaal6hb2vg7audpd4d4mcf5zluymff6sq"
}

variable "user_ocid" {
  type    = string
  default = "ocid1.user.oc1..aaaaaaaanmas3kbmeuvrmkg23l3zz3h5x2g7epmynfjhpixfnxwqqywy6nuq"
}

variable "openid_config_url" {
  type    = string
  default = "https://idcs-d8266c23006f431e89b9690c2f60bc1b.identity.oraclecloud.com/.well-known/openid-configuration"
}

variable "compartment_name" {
  type    = string
  default = "vault-dev"
}

variable "client_application_id" {
  type    = string
  default = "kco-5e0d83c-c408-42c7-b3f2-c86cd6bcda56"
}

variable "oci_key_policy" {
  type    = string
  default = "oci-key-policy"
}

variable "oci_key_policy_file" {
  type    = string
  default = "/server_certs/oci-key-policy.txt"
}

variable "oci_vault_policy" {
  type    = string
  default = "oci-vault-policy"
}

variable "oci_vault_policy_file" {
  type    = string
  default = "/server_certs/oci-vault-policy.txt"
}
