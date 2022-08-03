# Create a DSM Connection

This example shows how to:
- Create a DSM connection
- Add a DSM domain resource to the connection

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure DSM parameters required to create DSM keys
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

## Configure DSM Credentials and Domains

### Configure for all DSM examples

Update values in scripts/dsm_vars.sh and run the script.

This updates all dsm_vars.tf files found in the subdirectories.

### Configure for this example only

Edit dsm_vars.tf in this directory and update with your values.

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
