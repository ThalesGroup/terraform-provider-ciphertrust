# Adds a new Registration Token on CipherTrust Manager

This example shows how to:
- Add a new Registration Token

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure parameters required to add a registration token
- Run the example


## Configure CipherTrust Manager

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
  domain   = "cm-domain"
  bootstrap = "no"
}
```

## Configure Registration Token information
Edit the Registration Token resource configuration in main.tf with actual values
```bash
data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "%2FC%3DUS%2FST%3DTX%2FL%3DAustin%2FO%3DThales%2FCN%3DCipherTrust%20Root%20CA"
  }
}

output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}

resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources
Resources must be destroyed before another sample script using the same domain name is run.

```bash
terraform destroy
```

Run this step even if the apply step fails.