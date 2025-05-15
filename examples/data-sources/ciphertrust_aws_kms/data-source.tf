# To return details of all AWS KMS resources no parameters are required
data "ciphertrust_aws_kms" "all_kms" {
}

# To return details of all AWS KMS resources in a specific connection
data "ciphertrust_aws_kms" "by_connection_name" {
  aws_connection = "connection name"
}

# To return details specific KMS
data "ciphertrust_aws_kms" "by_kms_name" {
  kms_name = "kms name"
}

# Create a key using details returned from the datasource
resource "ciphertrust_aws_key" "aws_key_by_kms_name" {
  customer_master_key_spec = "RSA_2048"
  kms                      = "8b5ee431-eda1-49a8-b587-2b3f50524133"
  key_usage                = "ENCRYPT_DECRYPT"
  region                   = "us-east-1"
}
