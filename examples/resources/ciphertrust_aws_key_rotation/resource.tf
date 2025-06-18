resource "ciphertrust_aws_key_rotation" "rotate" {
  key_id = ciphertrust_aws_key.key_id
}
