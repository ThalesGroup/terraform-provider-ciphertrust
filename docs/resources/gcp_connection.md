---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_gcp_connection Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_gcp_connection (Resource)



## Example Usage

```terraform
resource "ciphertrust_gcp_connection" "connection" {
  key_file    = "gcp-key-file.json"
  name        = "gcp_connection_name"
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- **key_file** (String) Path to or data of a Google Cloud Service Account key file.
- **name** (String) Unique connection name.

### Optional

- **cloud_name** (String) Name of the cloud. Options: gcp. Default is gcp.
- **description** (String) Description of the Google Cloud connection.
- **meta** (String) Optional end-user or service data stored with the connection.

### Read-Only

- **id** (String) CipherTrust Google Cloud connection ID.


