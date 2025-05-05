# Retrieve details using the terraform resource ID
data "ciphertrust_aws_xks_key" "by_resource_id" {
  id = ciphertrust_aws_xks_key.aws_xks_key.id
}

# Retrieve details using the CipherTrust key ID
data "ciphertrust_aws_xks_key" "by_key_id" {
  key_id = ciphertrust_aws_xks_key.aws_xks_key.key_id
}

# Retrieve details using the AWS key ARN (applicable only for linked key)
data "ciphertrust_aws_xks_key" "by_arn" {
  arn = ciphertrust_aws_xks_key.aws_xks_key.arn
}

# Retrieve details using the alias and a region (applicable only for linked key)
data "ciphertrust_aws_xks_key" "by_alias_and_region" {
  alias  = ["key_name"]
  region = "region"
}
