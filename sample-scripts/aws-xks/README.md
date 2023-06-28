# Create resources for AWS XKS

This example shows how to:
- Create an AWS XKS unlinked key with Ciphertrust Manager as key source
- Create an AWS XKS unlinked key with Luna as key source

Following steps are required for both of the above:
- Create an AWS connection
- Create KMS account
- Create external key store in KMS account
- Create AWS XKS (HYOK) key

Following steps are required for Ciphertrust Manager as key source: 
- Create Ciphertrust Manager AES 256 symmetric key, unexportable, undeletable key with usage mask containing - Encrypt, Decrypt, Wrap, Unwrap).

Following steps are required for Luna as key source:
- Create luna HSM server
- Create luna HSM connection
- Create luna partition
- Create an AES-256 symmetric Luna HSM key with following attributes:
  - CKA_SENSITIVE = TRUE
  - CKA_ENCRYPT = TRUE
  - CKA_DECRYPT = TRUE
  - CKA_WRAP = TRUE
  - CKA_UNWRAP = TRUE
- Create virtual key using above Luna HSM key

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure Luna HSM parameters required to create connection
- Configure AWS parameters required to create AWS custom keystore
- Run the example

## Configure CipherTrust Manager

### Use environment variables

```bash
export CM_ADDRESS=https://cm-address
export CM_USERNAME=cm-username
export CM_PASSWORD=cm-password
export CM_DOMAIN=cm-domain
```
### Use a configuration file

Create a ~/.ciphertrust/config file and configure these keys with your values.

```bash
address = https://cm-address
username = cm-username
password = cm-password
domain = cm-domain
```

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
  domain   = "cm-domain"
}
```

## Configure AWS Credentials

### Use environment variables

```bash
export AWS_ACCESS_KEY_ID=access-key-id
export AWS_SECRET_ACCESS_KEY=secret-access_key
```

### Edit the connection resource in the script

```bash
resource "ciphertrust_aws_connection" "aws-connection" {
  name              = "aws-connection"
  access_key_id     = "access-key-id"
  secret_access_key = "secret-access_key"
}
```

##  AWS Key Policy

All keys will be assigned the default AWS key policy.

If you wish to assign a policy edit main.tf and add one of these policy blocks to the key resource.

```bash
key_policy {
  key_admins = ["aws-iam-user"]
  key_users  = ["aws-iam-user"]
}
```

```bash
key_policy {
   policy = <<-EOT
		{"Version":"2012-10-17","Id":"kms-tf-1","Statement":[{"Sid":"Enable IAM User Permissions 1","Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:*","Resource":"*"}]}
  EOT
}
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

Resources must be destroyed before another sample script using the same cloud is run.

```bash
terraform destroy
```
Run this step even if the apply step fails.
