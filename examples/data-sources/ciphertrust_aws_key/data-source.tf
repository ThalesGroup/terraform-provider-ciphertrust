# Retrieve details using the terraform resource ID
data "ciphertrust_aws_key" "by_resource_id" {
  id = ciphertrust_aws_key.aws_key.id
}

# Retrieve details using the CipherTrust key ID
data "ciphertrust_aws_key" "by_key_id" {
  key_id = ciphertrust_aws_key.aws_key.key_id
}

# Retrieve details using the AWS key ARN
data "ciphertrust_aws_key" "by_arn" {
  arn = ciphertrust_aws_key.aws_key.arn
}

# Retrieve details using the alias and a region
data "ciphertrust_aws_key" "by_alias_and_region" {
  alias  = ["key_name"]
  region = "region"
}
