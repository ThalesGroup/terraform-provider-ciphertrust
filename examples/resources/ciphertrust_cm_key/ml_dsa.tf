# Create an ML-DSA post-quantum signing key using the ML-DSA-65 parameter set
# (NIST FIPS 204 security level 3). Requires CipherTrust Manager with post-quantum
# cryptography support.

resource "ciphertrust_cm_key" "mldsa_key" {
  name                 = "my-mldsa-key"
  algorithm            = "ml-dsa"
  ml_dsa_parameter_set = "ML-DSA-65"
  usage_mask           = 3
  undeletable          = false
  unexportable         = false
}

output "mldsa_key_id" {
  value = ciphertrust_cm_key.mldsa_key.id
}
