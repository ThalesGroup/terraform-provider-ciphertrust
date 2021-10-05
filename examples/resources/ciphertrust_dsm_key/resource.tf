resource "ciphertrust_dsm_key" "dsm_key" {
  name            = "dsm_key_name"
  algorithm       = "AES256"
  domain          = ciphertrust_dsm_domain.dsm_domain.id
  encryption_mode = "CBC"
  extractable     = true
  object_type     = "symmetric"
}
