# Create CloudHSM key resources for AWS CloudHSM

This example shows how to:
- Create an AWS CloudHSM key with Ciphertrust Manager

Following steps are required for above:
- Create an AWS connection
- Create KMS account
- Create CloudHSM key store in KMS account
- Create CloudHSM key

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure AWS parameters required to create AWS custom keystore
- Run the example to create CloudHSM key.

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

##  Updating of parameters

Default values in `aws_cloudhsm_key_vars.tf` will be used to create resources.

If you wish to update parameters either update `aws_cloudhsm_key_vars.tf` or update `main.tf` to the resource directly.

```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

- Update the Ciphertrust Manager key to be deletable before deleting the Ciphertrust Manager key.
- CloudHSM key store can be deleted only after deleting keys in it.
- For CloudHSM key, key can be scheduled to be deleted between 7-30 days.
- Resources must be destroyed before another sample script using the same cloud is run.

```bash
terraform destroy
```
Run this step even if the apply step fails.
