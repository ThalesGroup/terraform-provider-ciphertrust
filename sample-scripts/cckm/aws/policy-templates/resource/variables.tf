variable "aws_key_user" {
  description = "AWS IAM user name to add as a key user in the policy template"
  type        = string
}

variable "aws_key_admin" {
  description = "AWS IAM user name to add as a key admin in the policy template"
  type        = string
}

variable "aws_key_user_role" {
  description = "AWS IAM role name to add as a key user role in the policy template"
  type        = string
}

variable "aws_key_admin_role" {
  description = "AWS IAM role name to add as a key admin role in the policy template"
  type        = string
}
