# This resource is dependent on a ciphertrust_aws_connection resource
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "aws_connection_name"
}

# Create a kms resource without using the ciphertrust_aws_account_details data-source and assign it to the connection
resource "ciphertrust_aws_kms" "kms" {
  account_id     = ["aws-account-id"]
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "kms-name"
  regions        = ["aws-region", "aws-region"]
}

# Create a kms resource using the ciphertrust_aws_account_details data-source and assign it to the connection
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "kms-name"
  regions = [data.ciphertrust_aws_account_details.account_details.regions[0],
  data.ciphertrust_aws_account_details.account_details.regions[1]]
}

# Create an AWS key
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = ciphertrust_aws_kms.kms.regions[0]
}
