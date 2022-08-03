# Import Key Material from a HSM Luna Key to an AWS Key

This example shows how to:
- Create an AWS connection
- Create a HSM-Luna connection
- Import key material from a HSM Luna key to an AWS key

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure AWS parameters required to create AWS keys
- Configure HSM Luna parameters required to create HSM Luna keys
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

Create a ~/.ciphertrust/config file and configure these keys with your values

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

### Edit the connection resource in main.tf

```bash
resource "ciphertrust_aws_connection" "aws-connection" {
  name              = "aws-connection"
  access_key_id     = "access-key-id"
  secret_access_key = "secret-access_key"
}
```
## Configure HSM Luna Credentials and Partitions

### Configure for all HSM Luna examples

Update values in scripts/hsm_vars.sh and run the script.

This updates all hsm_vars.tf files found in the subdirectories.

### Configure for this example only

Edit hsm_vars.tf in this directory and update with your values.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

Resources must be destroyed before another sample script using the same clouds is run.

```bash
terraform destroy
```
Run this step even if the apply step fails.
