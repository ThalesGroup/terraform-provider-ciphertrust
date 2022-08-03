variable "issuer" {
  type    = string
  default = "gcp-cse-issuer"
}

variable "authentication_audience" {
  type    = string
  default = "gcp-cse-authentication-audience"
}

variable "endpoint_url_hostname" {
  type    = string
  default = "gcp-cse-endpoint-url-hostname"
}
