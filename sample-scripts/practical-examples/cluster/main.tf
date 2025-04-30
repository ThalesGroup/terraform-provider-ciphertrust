terraform {
  required_providers {
    ciphertrust = {
      source = "ThalesGroup/ciphertrust"
      version = "0.11.1"
    }

    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region
}

# Create the instances
module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "~> 3.0"

  for_each = toset(var.instance_names)

  name = "ciphertrust-instance-${each.key}"

  ami                    = var.aws_ami
  instance_type          = var.aws_instance_type
  key_name               = var.aws_key_name
  vpc_security_group_ids = var.aws_security_group_ids
  subnet_id              = var.aws_subnet_id

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

provider "ciphertrust" {
  // destroy cluster can take almost a minute so give us a bit of a buffer
  rest_api_timeout = 120
}

resource "ciphertrust_cluster" "cluster" {
  dynamic "node" {
    for_each = module.ec2_instance
    content {
      host           = node.value.private_ip
      public_address = node.value.public_ip
    }
  }
}
