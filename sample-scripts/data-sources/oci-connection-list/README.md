# Lists OCI connections

This example shows how to:
- Fetch a list of Oracle OCI connections matching a set of filters

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the filters used to narrow down the connection list
- Run the example

## Configure CipherTrust Manager

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
}
```

## Configure the connection list filters

Edit the data source configuration in main.tf with actual values.

```bash
data "ciphertrust_oci_connection_list" "example_oci_connection" {
  filters = {
    name = "oci-connection"
  }
}
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
