# Create a Policy Template for AWS Keys

This example shows how to:
- Create an AWS connection
- Create policy templates
- Assign policy templates to keys

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure AWS parameters required to create policy templates and AWS keys
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

##  Configure Policy Template Variables

Update values in policy_vars.tf found in this directory.

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
