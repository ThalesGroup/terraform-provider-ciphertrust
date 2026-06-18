# Retrieve details using the terraform resource ID
data "ciphertrust_aws_custom_keystore" "by_resource_id" {
  id = "8b5ee431-eda1-49a8-b587-2b3f50524133"
}
