# Retrieve details using the terraform resource ID
data "ciphertrust_aws_xks_key" "by_resource_id" {
  id = "52bf7dfd-fea6-4f26-af5e-9c1e425ce504"
}

# Retrieve details using the CipherTrust key ID
data "ciphertrust_aws_xks_key" "by_key_id" {
  key_id = "b4be6149-9903-48cf-ae0b-e468ba8b7293"
}

# Retrieve details using the AWS key ARN (applicable only for linked key)
data "ciphertrust_aws_xks_key" "by_arn" {
  arn = "arn:aws:kms:ap-south-2:999999999999:key/7c03617d-4a29-48aa-98cf-ea9c8bced197"
}

# Retrieve details using the alias and a region (applicable only for linked key)
data "ciphertrust_aws_xks_key" "by_alias_and_region" {
  alias  = ["key_name"]
  region = "region"
}
