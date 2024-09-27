---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "ciphertrust_smb_connection Resource - terraform-provider-ciphertrust"
subcategory: ""
description: |-
  
---

# ciphertrust_smb_connection (Resource)





<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) Unique connection name
- `password` (String) Password for SMB share.
- `username` (String) sername for accessing SMB share.

### Optional

- `description` (String) This is the description of the Smb connection name.
- `domain` (String) Domain for SMB share.
- `host` (String) Hostname or FQDN of SMB share.
- `port` (String) Port where SMB service runs on host (usually 445).
- `products` (List of String) Array of the CipherTrust products associated with the connection.

### Read-Only

- `id` (String) The ID of this resource.