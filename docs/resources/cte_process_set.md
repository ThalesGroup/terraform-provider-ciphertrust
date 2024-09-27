---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_cte_process_set Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_cte_process_set (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) This is the name of the process set.

### Optional

- `description` (String) (Updateable) Description of process set
- `processes` (Block List) Process set list. (see [below for nested schema](#nestedblock--processes))

### Read-Only

- `id` (String) The ID of this resource.

<a id="nestedblock--processes"></a>
### Nested Schema for `processes`

Optional:

- `directory` (String) (Updateable) ProcessDirectory of the process to be added to the process set.
- `file` (String) (Updateable) File name of the process to be added to the process set.
- `signature` (String) (Updateable) ID of the signature set to link to the process set.