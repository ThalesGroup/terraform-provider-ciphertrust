# Create Oidc Connection on Ciphertrust Manager.

This example shows how to:
- Create a Oidc Connection on Ciphertrust Manager.

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


### Edit the connection resource in main.tf

```bash
resource "ciphertrust_oidc_connection" "OIDCConnection" {
        name = "Unique_connection_name."
        description = "connection_description"
        products = "Array of the CipherTrust products associated with the connection."
        client_id = "clientID for the connection."
        client_secret = "Client Secret of the OIDC connection."
        url = "url for the connection."
}
```

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