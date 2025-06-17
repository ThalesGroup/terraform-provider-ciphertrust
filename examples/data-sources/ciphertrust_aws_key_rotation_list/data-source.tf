data "ciphertrust_aws_key_rotation_list" "rotation_list" {
  key_id = ciphertrust_aws_key.key.key_id
}
