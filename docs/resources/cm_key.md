---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_cm_key Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-

---

# ciphertrust_cm_key (Resource)



## Example Usage

```terraform
resource "ciphertrust_cm_key" "cm_key" {
  name      = "key_name"
  algorithm = "RSA"
  key_size  = 4096
}
```

<!-- schema generated by tfplugindocs -->
## Argument Reference

### Required

- **algorithm** (String) Algorithm of the key. Options: AES, EC and RSA.
- **name** (String) Name of the key.

### Optional

- **curve** (String) Curve for an EC key. Options: secp256k1, secp384r1, secp521r1 and prime256v1. Default is secp384r1.
- **key_size** (Number) Required for RSA keys. Optional for AES keys. Defaults to 256 for AES keys.

### Read-Only

- **id** (String) CipherTrust key ID.

