terraform {
  required_providers {
    ciphertrust = {
      source = "thalesgroup.com/oss/ciphertrust"
      version = "1.0.0"
    }
  }
}
provider "ciphertrust" {
  address = "https://192.168.2.137"
  username = "admin"
  password = "ChangeIt01!"
  bootstrap = "no"
}

resource "ciphertrust_aws_connection" "aws_connection" {
    name        = "tf-aws-connection"
    products = [
      "cckm"
    ]
    access_key_id = "ACCESS_KEY_ID"
    secret_access_key = "SECRET_ACCESS_KEY"
    cloud_name= "aws"
    aws_region = "us-east-1"
    description = "Terraform Generated"
    labels = {
        "environment" = "devenv"
    }
    meta = {
        "custom_meta_key1" = "custom_value1"
        "customer_meta_key2" = "custom_value2"
    }
}

output "aws_connection_id" {
  value = ciphertrust_aws_connection.aws_connection.id
}

output "aws_connection_name" {
  value = ciphertrust_aws_connection.aws_connection.name
}

data "ciphertrust_aws_connection_list" "aws_connections_list" {
}

output "aws_connections" {
  value = data.ciphertrust_aws_connection_list.aws_connections_list
}