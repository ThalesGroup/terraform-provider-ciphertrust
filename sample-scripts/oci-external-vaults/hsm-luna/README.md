# Create a HSM-Luna Key and add it to an OCI External Vault

This example shows how to:
- Create an OCI Cloud connection
- Create a HSM-Luna connection
- Create an OCI external vault allowing only hsm-luna keys
 
These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure OCI parameters required to create keys in the external vault
- Configure HSM-Luna parameters required to create HSM-Luna keys
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

## Configure OCI Cloud Credentials

### Configure for all OCI Cloud examples

Update values in scripts/oci_vars.sh and run the script.

This updates all oci_vars.tf files found in the subdirectories.

### Configure for this example only

Edit oci_vars.tf in this directory and update with your values.

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

Resources must be destroyed before another sample script using the same cloud is run.

```bash
terraform destroy
```
Run this step even if the apply step fails.
