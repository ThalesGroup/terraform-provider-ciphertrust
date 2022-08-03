# Create an AWS connection without using environment variables
resource "ciphertrust_aws_connection" "aws_connection" {
  name              = "connection-name"
  access_key_id     = "access-key-id"
  secret_access_key = "secret-access-key"
}

# Create an AWS connection using the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables
resource "ciphertrust_azure_connection" "azure_connection" {
  name = "connection-name"
}

# Create a ciphertrust_aws_kms resource and assign it to the connection
resource "ciphertrust_aws_kms" "kms" {
  account_id     = "aws-account-id"
  aws_connection = ciphertrust_aws_connection.aws_connection.id
  name           = "kms-name"
  regions        = ["aws-region", "aws-region"]
}

# Create an AWS key
resource "ciphertrust_aws_key" "aws_key" {
  kms    = ciphertrust_aws_kms.kms.id
  region = "aws-region"
}
