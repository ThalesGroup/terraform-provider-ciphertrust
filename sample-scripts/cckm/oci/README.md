# OCI Resources and Data Sources

These steps explain how to configure CipherTrust Manager Provider parameters required to run the examples.

## Configure CipherTrust Manager

### Use environment variables

```bash
export CIPHERTRUST_ADDRESS=https://cm-address
export CIPHERTRUST_USERNAME=cm-username
export CIPHERTRUST_PASSWORD=cm-password
# domain and auth_domain default to "root" - set only if different
export CIPHERTRUST_DOMAIN=root
export CIPHERTRUST_AUTH_DOMAIN=root
```
### Use a configuration file

Create a ~/.ciphertrust/config file and configure these keys with your values.

```bash
address     = https://cm-address
username    = cm-username
password    = cm-password
# domain and auth_domain default to "root"
domain      = root
auth_domain = root
```

### Edit the provider block in main.tf

```bash
provider "ciphertrust" {
  address     = "https://cm-address"
  username    = "cm-username"
  password    = "cm-password"
  # domain and auth_domain default to "root"
  domain      = "root"
  auth_domain = "root"
}
```

## Configure OCI Credentials

The OCI connection `key_file` argument is write-only, so these examples require
Terraform 1.11 or later.

OCI connection credentials are supplied via Terraform variables. Set the following
environment variables before running a script:

```bash
export TF_VAR_oci_key_file=$CCKM_OCI_KEY_FILE
export TF_VAR_oci_pub_key_fingerprint=$CCKM_OCI_FINGERPRINT
export TF_VAR_oci_region=$CCKM_OCI_REGION
export TF_VAR_oci_tenancy_ocid=$CCKM_OCI_CONN_TENANCY
export TF_VAR_oci_user_ocid=$CCKM_OCI_USER
# Required for byok_keys_and_versions, native_keys_and_versions, native_key_types,
# key_rotation_and_sync and datasources only:
export TF_VAR_oci_vault_ocid=$CCKM_OCI_VAULT
```

## Examples

| Directory | Shows |
|-----------|-------|
| acls | Vault ACLs for a user and a group |
| vaults | Adding a vault and listing vaults |
| byok_keys_and_versions | BYOK key with BYOK and native versions |
| native_keys_and_versions | Native key with BYOK and native versions |
| native_key_types | AES, RSA and ECDSA native keys, tags, deletion wait |
| key_rotation_and_sync | Rotation and synchronization schedulers, key auto-rotation |
| datasources | Connection, compartment and bucket datasources |

key_rotation_and_sync needs two applies to enable key rotation:

```bash
terraform apply
terraform apply -var="enable_rotation=true"
```

native_key_types uses SOFTWARE protection. For HSM keys use a Virtual Private Vault and run
`terraform apply -var="oci_protection_mode=HSM"`.

## Import Existing Resources

Resources can be imported by CipherTrust Manager resource ID after adding a matching resource
block to the configuration:

```bash
terraform import ciphertrust_oci_vault.vault <vault-cm-id>
terraform import ciphertrust_oci_key.native_key <key-cm-id>
terraform import ciphertrust_oci_byok_key.byok_key <key-cm-id>
```

Key versions use the composite ID `<key-cm-id>.<version-id>`. ACLs use
`<vault-cm-id>::<user|group>::<identity>`.

## Run Examples

If a `variables.tf` file exists in the script directory, the declared variables must be supplied
before running the script. Use `TF_VAR_` environment variables to provide values without
hard-coding them in source files (see Configure OCI Credentials above).

```bash
terraform init
terraform apply
```

## Destroy Resources

To avoid conflicts with existing resources run terraform destroy before running another script.

```bash
terraform destroy
```
Run this step even if the apply step fails.
