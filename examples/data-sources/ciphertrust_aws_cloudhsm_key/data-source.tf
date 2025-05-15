# Retrieve details using the AWS key ARN
data "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_by_arn" {
  arn = "arn:aws:kms:ap-south-2:999999999999:key/04774caa-f317-4955-a5d8-37ea698bd758"
}

# Retrieve details using the alias and a region
data "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_by_alias_and_region" {
  alias  = ["key_name"]
  region = "region"
}

# Retrieve details using the terraform resource ID
data "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_by_resource_id" {
  id = "3951b763-e301-4f6e-a8e4-2d92f85c3584"
}

# Retrieve details using the CipherTrust key ID
data "ciphertrust_aws_cloudhsm_key" "ciphertrust_aws_cloudhsm_key_by_key_id" {
  key_id = "77b4acd3-80e4-4270-81b5-11bb13b8053a"
}
