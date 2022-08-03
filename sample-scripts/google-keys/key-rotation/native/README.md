# Schedule Rotation of Google Cloud Keys using Google Cloud as the Key Source

This example shows how to:
- Create a connection to Google Cloud
- Configure a scheduled rotation job for Google Cloud keys using Google Cloud as the key source
- Create a Google Cloud key that will be rotated by the scheduler

The following steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
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
