# Lists CipherTrust Manager groups

This example shows how to:
- Fetch a list of CipherTrust Manager local groups matching a set of filters

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the filters used to narrow down the group list
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

## Configure the group list filters

Edit the data source configuration in main.tf with actual values.

```bash
data "ciphertrust_cm_groups_list" "groups_list" {
  filters = {
    name = "Key Users"
  }
}
```

Supported filter keys: `name`, `users`, `connection`, `clients`, `skip`, `limit`. If neither `skip`
nor `limit` is set, the data source paginates internally and returns every matching group.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
