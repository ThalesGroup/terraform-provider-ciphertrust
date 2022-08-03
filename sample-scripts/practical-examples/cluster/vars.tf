variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "aws_access_key" {
  type    = string
  default = "access-key-goes-here"
}

variable "aws_secret_key" {
  type    = string
  default = "secret-key-goes-here"
}

variable "aws_ami" {
  type    = string
  default = "ami-0a9fd26e3ce18ddf8"
}

variable "aws_instance_type" {
  type    = string
  default = "t2.large"
}

variable "aws_key_name" {
  type    = string
  default = "test-key-01"
}

variable "aws_security_group_ids" {
  type    = list
  default = ["sg-goes-here"]
}

variable "aws_subnet_id" {
  type    = string
  default = "subnet-id-goes-here"
}

variable "instance_names" {
  type    = list
  default = ["one", "two"]
}
