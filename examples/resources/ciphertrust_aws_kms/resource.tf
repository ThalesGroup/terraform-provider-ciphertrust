resource "ciphertrust_aws_kms" "kms" {
  account_id     = data.ciphertrust_aws_account_details.account_details.account_id
  aws_connection = ciphertrust_aws_connection.connection.id
  name           = "kms_name"
  regions        = data.ciphertrust_aws_account_details.account_details.regions
}
