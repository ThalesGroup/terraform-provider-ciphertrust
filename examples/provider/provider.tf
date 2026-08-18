terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "~> 1.0"
    }
  }
}

variable "ciphertrust_password" {
  description = "CipherTrust Manager user password. Set via TF_VAR_ciphertrust_password, or omit this variable and use the CIPHERTRUST_PASSWORD environment variable."
  type        = string
  sensitive   = true
}

provider "ciphertrust" {
  address     = "https://ip_or_hostname_of_cm"
  username    = "username"
  password    = var.ciphertrust_password
  auth_domain = "authentication-domain"

  # Optional: PEM-encoded CA bundle for private PKI / internally-issued certs.
  # Use this when CipherTrust Manager presents a certificate that is not in
  # the system trust store (air-gapped, self-issued, internal CA, etc.).
  # ca_cert = "/etc/ssl/certs/my-internal-ca.pem"

  # Optional: disable TLS certificate verification. NOT RECOMMENDED. Use this
  # only for local development or testing, never in production. The provider
  # emits a warning at plan time when this is enabled.
  # no_ssl_verify = true
}
