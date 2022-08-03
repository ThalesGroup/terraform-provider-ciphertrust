variable "hsm_certificate" {
  type    = string
  default = "hsm-server-cert-path"
}

variable "hsm_hostname" {
  type    = string
  default = "hsm-hostname"
}

variable "hsm_partition_password" {
  type    = string
  default = "hsm-partition-password"
}

variable "hsm_partition_label" {
  type    = string
  default = "hsm-partition-label"
}

variable "hsm_partition_serial_number" {
  type    = string
  default = "hsm-partition-sn"
}