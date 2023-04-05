variable "gcp_key_file" {
  type    = string
  default = "../../../server_certs/gcp-key-file.json"
}

variable "gcp_project" {
  type    = string
  default = "gemalto-kyloeng"
}

variable "keyring_ex1" {
  type    = string
  default = "projects/gemalto-kyloeng/locations/global/keyRings/CCKM-Automation1"
}
