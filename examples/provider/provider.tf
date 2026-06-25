provider "ciphertrust" {
  address     = "https://ip_or_hostname_of_cm"
  username    = "username"
  password    = "password"
  auth_domain = "authentication-domain"

  # Optional: PEM-encoded CA bundle for private PKI / internally-issued certs.
  # Use this when CipherTrust Manager presents a certificate that is not in
  # the system trust store (air-gapped, self-issued, internal CA, etc.).
  # ca_cert = "/etc/ssl/certs/my-internal-ca.pem"

  # Optional: disable TLS certificate verification. NOT RECOMMENDED — use
  # only for local development or testing. The provider will emit a warning
  # at plan time when this is enabled.
  # no_ssl_verify = true
}
