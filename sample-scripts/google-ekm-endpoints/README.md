# Create a Google Cloud Encryption Key Manager Endpoint

This example shows how to:
- Create a Google Cloud connection
- Create a Google Cloud External Key Manager Endpoint using minimum parameters
- Create a Google Cloud External Key Manager Endpoint
- Create a Google Cloud External Key Manager UDE Endpoint

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure Google Cloud EKM parameters required to create the endpoint
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

## Configure Google Cloud Credentials and Keyrings

### Configure for all Google Cloud examples

Update values in scripts/gcp_vars.sh and run the script.

This updates all gcp_vars.tf files found in the subdirectories.

### Configure for this example only

Edit gcp_vars.tf in this directory and update with your values.

## Configure Google Cloud EKM Parameters

### Configure for all CSE examples

Update values in scripts/gcp_ekm_vars.sh and run the script.

This updates all gcp_ekm_vars.tf files found in the subdirectories.

### Configure for this example only

Edit gcp_ekm_vars.tf in this directory and update with your values.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
