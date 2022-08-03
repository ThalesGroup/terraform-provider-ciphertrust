# Build a CM cluster on AWS

This example shows how to:
- Create a CipherTrust Manager Cluster on AWS

These steps explain how to:
- Configure the AWS and CipherTrust Manager Provider parameters required to run the examples
- Run the example


### Edit the vars.tf file
```bash
variable "aws_region" {
  type    = string
  default = "us-east-1"
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
```

## Configure AWS Credentials

### Use environment variables

```bash
export AWS_ACCESS_KEY_ID=access-key-id
export AWS_SECRET_ACCESS_KEY=secret-access_key
```


## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
