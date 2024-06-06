---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_oci_regions Data Source - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_oci_regions (Data Source)

This data-source will return a list of available regions.

## Example Usage

```terraform
# Get a list of OCI regions available to the connection using the connection ID
data "ciphertrust_oci_regions" "oci_regions_by_connection_id" {
  connection_id = "oci connection id"
}

# Get a list of OCI regions available to the connection using the connection name
data "ciphertrust_oci_regions" "oci_regions_by_connection_name" {
  connection_id = "oci connection name"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `connection_id` (String) CipherTrust connection name or ID.

### Read-Only

- `id` (String) The ID of this resource.
- `oci_regions` (List of String) A list of regions available to the connection.