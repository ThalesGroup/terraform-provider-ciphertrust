# Retrieve details using a terraform resource ID
data "ciphertrust_aws_key" "by_resource_id" {
  id = "ap-south-2\\6fe5ebd3-8f02-4870-ba35-b433f9e0ea7c"
}

# Retrieve details using a CipherTrust key ID
data "ciphertrust_aws_key" "by_key_id" {
  key_id = "77b4acd3-80e4-4270-81b5-11bb13b8053a"
}

# Retrieve details using an AWS key ARN
data "ciphertrust_aws_key" "by_arn" {
  arn = "arn:aws:kms:ap-south-2:999999999999:key/6abfe573-4506-4ce4-8672-3af42f552d42"
}

# Retrieve details using the alias and a region of a key
data "ciphertrust_aws_key" "by_alias_and_region" {
  alias  = ["key-name"]
  region = "region"
}
