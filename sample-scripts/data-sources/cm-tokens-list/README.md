# Lists CipherTrust Manager registration tokens

This example shows how to:
- Fetch a list of client registration tokens matching a set of filters

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure the filters used to narrow down the token list
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

## Configure the token list filters

Edit the data source configuration in main.tf with actual values.

```bash
data "ciphertrust_cm_tokens_list" "tokens_list" {
  filters = {
    labels = "environment=devenv"
  }
}
```

Supported filter keys: `id`, `token`, `label`, `labels`. Each returned token includes its secret
`token` value, so any output referencing this data source must be marked `sensitive = true`.

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources

```bash
terraform destroy
```
