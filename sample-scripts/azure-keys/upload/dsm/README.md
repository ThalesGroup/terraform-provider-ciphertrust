# Upload a DSM Key to Azure

This example shows how to:
- Create an Azure connection
- Create a DSM connection
- Create a DSM key and upload it to Azure

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure Azure parameters required to create Azure keys
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

## Configure Azure Credentials

### Use environment variables

```bash
export ARM_CLIENT_ID=client-id
export ARM_CLIENT_SECRET=client-secret
export ARM_TENANT_ID=tenant-id
```

### Edit the connection resource in main.tf

```bash
resource "ciphertrust_azure_connection" "azure_connection" {
  name          = "azure-connection"
  client_id     = "client-id"
  client_secret = "client-secret"
  tenant_id     = "tenant-id"
}
```

## Configure Azure Vaults

### Configure for all Azure examples

Update values in scripts/azure_vars.sh and run the script.

This updates all azure_vars.tf files found in the subdirectories.

### Configure for this example only

Edit azure_vars.tf in this directory and update with your values.

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

## Delete the Resources

Resources must be destroyed before another sample script using the same clouds is run.

```bash
terraform destroy
```
It's important to run this step even if the apply step fails.
