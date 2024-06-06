# Create an issuer using an unprotected openid_config_url
resource "ciphertrust_oci_issuer" "unprotected_openid_config_url" {
  name              = "issuer-name"
  openid_config_url = "unprotected openid-config-url"
}

# Create an issuer using a protected openid_config_url
resource "ciphertrust_oci_issuer" "protected_openid_config_url" {
  name               = "issuer-name"
  openid_config_url  = "protected openid-config-url"
  jwks_uri_protected = true
  client_id          = "client id"
  client_secret      = "client secret"
}

# Create an issuer using an unprotected jwks uri
resource "ciphertrust_oci_issuer" "unprotected_jwks_and_issuer" {
  name     = "issuer-name"
  jwks_uri = "unprotected jwks-uri"
  issuer   = "oci issuer"
}

# Create an issuer using a protected jwks uri
resource "ciphertrust_oci_issuer" "protected_jwks_and_issuer" {
  name               = "issuer name"
  jwks_uri           = "unprotected jwks-uri"
  issuer             = "oci issuer"
  jwks_uri_protected = true
  client_id          = "client id"
  client_secret      = "client secret"
}
