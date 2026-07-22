# This resource is dependent on a ciphertrust_aws_connection resource
resource "ciphertrust_aws_connection" "aws_connection" {
  name = "name"
}

# Define a KMS resource using the ciphertrust_aws_account_details data-source
data "ciphertrust_aws_account_details" "account_details" {
  connection_id = ciphertrust_aws_connection.aws_connection.id
}

# Create a KMS resource
resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.aws_connection.id
  name          = "name"
  regions = [
    data.ciphertrust_aws_account_details.account_details.regions[0],
    data.ciphertrust_aws_account_details.account_details.regions[1],
  ]
}

# Archive an existing KMS by setting archive = true via update.
/*
resource "ciphertrust_aws_kms" "kms" {
  account_id    = data.ciphertrust_aws_account_details.account_details.account_id
  connection_id = ciphertrust_aws_connection.aws_connection.id
  name          = "name"
  regions       = [data.ciphertrust_aws_account_details.account_details.regions[0]]
  archive       = true
}
*/
