# Protect an Azure Storage Account with a CipherTrust Manager Key

This example shows how to:
- Create an Azure storage account
- Add an access policy to the storage account
- Create an Azure connection
- Create an RSA key
- Configure the storage account key

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure Azure parameters required to create Azure keys
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

## Configure Azure Variables

Edit vars.tf in this directory and update with your values.

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
