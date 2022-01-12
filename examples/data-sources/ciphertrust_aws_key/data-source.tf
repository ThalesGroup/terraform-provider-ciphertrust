# Get the AWS key details using the alias and optionally a region
data "ciphertrust_aws_key" "by_alias" {
  alias  = ["key_alias"]
  region = "us-east1"
}

# Get the AWS key details using the ARN
data "ciphertrust_aws_key" "by_arn" {
  arn = ciphertrust_aws_key.aws_key.arn
}

# Get the AWS key details using the AWS key id and optionally a region
data "ciphertrust_aws_key" "by_aws_key_id" {
  aws_key_id = ciphertrust_aws_key.aws_key.aws_key_id
  region     = "us-east1"
}

# Get the AWS key details using the terraform resource id
data "ciphertrust_aws_key" "by_resource_id" {
  id = ciphertrust_aws_key.aws_key.id
}

# Get the AWS key details using the CipherTrust key id
data "ciphertrust_aws_key" "by_key_id" {
  key_id = ciphertrust_aws_key.aws_key.key_id
}