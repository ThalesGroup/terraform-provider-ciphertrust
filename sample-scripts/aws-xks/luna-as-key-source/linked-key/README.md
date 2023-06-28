# Create resources for AWS XKS

This example shows how to:
- Create an AWS XKS linked key with Luna as key source

Following steps are required for above:
- Create an AWS connection
- Create KMS account
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
- Create external key store in KMS account
- Create AWS XKS (HYOK) key

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure AWS parameters required to create AWS custom keystore
- Configure Luna HSM server, connection and AES-256 key parameters required to create AWS HYOK key
- Run the example to create linked AWS HYOK key with Luna as key source.

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

## Configure Luna HSM parameters

- Download and copy luna client certificate from the Ciphertrust Manager. 
- Register client and assign partition on Luna HSM server by ssh to Luna HSM server.
- Update HSM parameters in `aws_xks_vars.tf` or update them directly in `main.tf`. 


##  Updating of parameters

Default values in aws_xks_vars.tf will be used to create resources.

If you wish to update parameters either update `aws_xks_vars.tf` or update `main.tf` to the resource directly.

```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

- Update the virtual key to be deletable before deleting the virtual key
- External key store can be deleted only after deleting HYOK (XKS) keys in it. 
- For linked HYOK (XKS) key, key can be scheduled to be deleted between 7-30 days.
- Resources must be destroyed before another sample script using the same cloud is run.

```bash
terraform destroy
```
Run this step even if the apply step fails.
