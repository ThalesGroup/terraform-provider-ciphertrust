resource "ciphertrust_hsm_key" "hsm_key" {
  attributes   = ["CKA_ENCRYPT", "CKA_DECRYPT"]
  mechanism    = "CKM_RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN"
  partition_id = ciphertrust_hsm_partition.hsm_partition.id
  key_size     = 2048
}

