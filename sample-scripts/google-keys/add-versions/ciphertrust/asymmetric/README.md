# Create a CipherTrust Manager Asymmetric Key Version

This example shows how to:
- Create a Google Cloud connection
- Create an asymmetric version of a Google Cloud key from a CipherTrust Manager key

Note: New versions can be added during create or update, this example can only show a new version being added during create.

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure Google Cloud parameters required to create Google Cloud keys
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

## Configure Google Cloud Credentials and Keyrings

### Configure for all Google Cloud examples

Update values in scripts/gcp_vars.sh and run the script.

This updates all gcp_vars.tf files found in the subdirectories.

### Configure for this example only

Edit gcp_vars.tf in this directory and update with your values.

## Run the Example

```bash
terraform init
terraform apply
```

## Delete the Resources

Resources must be destroyed before another sample script using the same clouds is run.

```bash
terraform destroy
```
It's important to run this step even if the apply step fails.
