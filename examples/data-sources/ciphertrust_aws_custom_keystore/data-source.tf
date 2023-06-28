# Retrieve details using the terraform resource ID
data "ciphertrust_aws_custom_keystore" "by_resource_id" {
  id = ciphertrust_aws_custom_keystore.custom_keystore.id
}
