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

# Retrieve details using the AWS key ID
data "ciphertrust_aws_key" "by_aws_key_id" {
  aws_key_id = "c3c1fa33-d8a9-48ca-8e91-98504798a605"
}

# Retrieve details using the AWS key ID and a region
data "ciphertrust_aws_key" "by_aws_key_id_and_region" {
  aws_key_id = "a44b00d1-2719-48c4-90a1-491fd67de30d"
  region = "ap-northeast-1"
}
