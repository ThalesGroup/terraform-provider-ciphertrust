# Retrieve the account ID and available regions for an AWS connection.
data "ciphertrust_aws_account_details" "details" {
  connection_id = "aws-prod-connection"
}

# Retrieve account details while assuming a specific IAM role.
data "ciphertrust_aws_account_details" "with_role" {
  connection_id   = "aws-prod-connection"
  assume_role_arn = "arn:aws:iam::123456789012:role/MyRole"
}
