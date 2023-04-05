---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_policy_attachments Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_policy_attachments (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `policy` (String) The ID for the policy to be attached.
- `principal_selector` (String) Selects which principals to apply the policy to. This can also be done using the conditions set while creating a policy.

### Optional

- `jurisdiction` (String) Jurisdiction to which the policy applies.

### Read-Only

- `id` (String) The ID of this resource.

