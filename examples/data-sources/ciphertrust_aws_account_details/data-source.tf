# Define an AWS connection
resource "ciphertrust_aws_connection" "aws_connection" {
  name              = "connection-name"
  access_key_id     = "access-key-id"
  secret_access_key = "secret-access-key"
}

# Use the connection ID to retrieve account details
data "ciphertrust_aws_account_details" "account_details" {
  aws_connection = ciphertrust_aws_connection.aws_connection.id
}

# Use the account details datasource elements to create a KMS resource
resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "kms-name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}
