---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_dsm_domain Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_dsm_domain (Resource)



## Example Usage

```terraform
resource "ciphertrust_dsm_domain" "dsm_domain" {
  dsm_connection = ciphertrust_dsm_connection.connection.id
  domain_id      = 4321
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **domain_id** (Number) DSM domain to add.
- **dsm_connection** (String) Name or ID of the DSM connection.

### Optional

- **description** (String) Description of the dsm domain.

### Read-Only

- **id** (String) CipherTrust DSM domain ID.


