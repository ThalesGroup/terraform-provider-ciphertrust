# Retrieve details using the AWS key ARN
data "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_by_arn" {
  depends_on = [
    ciphertrust_aws_cloudhsm_key.cloudhsm_key_1,
  ]
  arn = ciphertrust_aws_cloudhsm_key.cloudhsm_key_1.arn
}

# Retrieve details using the alias and a region
data "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_by_alias_and_region" {
  alias  = ["key_name"]
  region = "region"
}

# Retrieve details using the terraform resource ID
data "ciphertrust_aws_cloudhsm_key" "cloudhsm_key_by_resource_id" {
  id = ciphertrust_aws_cloudhsm_key.cloudhsm_key_1.id
}

# Retrieve details using the CipherTrust key ID
data "ciphertrust_aws_cloudhsm_key" "ciphertrust_aws_cloudhsm_keyby_key_id" {
  key_id = ciphertrust_aws_cloudhsm_key.cloudhsm_key_1.key_id
}
