# Lists CipherTrust Manager keys

This example shows how to:
- Fetch a list of cryptographic keys matching a set of filters

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the filters used to narrow down the key list
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

## Configure the key list filters

Edit the data source configuration in main.tf with actual values.

```bash
data "ciphertrust_cm_keys_list" "keys_list" {
  filters = {
    algorithm = "aes"
  }
}
```

Supported filter keys: `name` (supports `?`/`*` wildcards), `algorithm`, `id`, `uuid`, `muid`,
`keyId`, `size`, `curveid`, `parameterSet`, `version`, `uri`, `state`, `fields`, `metaContains`,
`objectType`, `skip`, `limit`, and more. If neither `skip` nor `limit` is set, the data source
paginates internally (pages of 10) and returns every matching key.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
