variable "issuer" {
  type    = string
  default = "gcp-cse-issuer"
}

variable "jwks_url" {
  type    = string
  default = "gcp-cse-jwks-url"
}

variable "open_id_configuration_url" {
  type    = string
  default = "gcp-cse-open-id_configuration_url"
}

variable "endpoint_url_hostname" {
  type    = string
  default = "gcp-cse-endpoint-url-hostname"
}
