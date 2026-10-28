# Azure Resources and Data Sources

These steps explain how to configure CipherTrust Manager Provider parameters required to run the examples.

## Scripts

| Directory | What it does |
|-----------|--------------|
| `vaults` | Lists the Key Vaults in a subscription with `ciphertrust_azure_vault_details`, adds one to CipherTrust Manager and lists it with `ciphertrust_azure_vault_list`. |
| `acls` | Creates a CipherTrust Manager user and group and gives each an ACL on the vault. |
| `keys` | Creates a native RSA key in the vault, then creates a CipherTrust Manager RSA key and uploads it to the vault. |
| `certificates` | Creates a native self-signed certificate in the vault. |
| `secrets` | Creates a secret in the vault. |

All scripts create their own Azure connection and add an existing Azure Key Vault to CipherTrust Manager.
A standard Key Vault is enough. No premium or HSM-backed vault is needed.

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

## Configure Azure Credentials

Azure connection credentials and the vault name are supplied via Terraform variables. Set the following
environment variables before running a script:

```bash
# The vaults and acls scripts use the first subscription the connection returns.
export TF_VAR_azure_subscription_id=azure-subscription-id
export TF_VAR_azure_client_id=azure-application-client-id
export TF_VAR_azure_tenant_id=azure-tenant-id
export TF_VAR_azure_client_secret=azure-client-secret
# Name of an existing Azure Key Vault the application can access
export TF_VAR_azure_non_purgeable_vault=vault-name
```

The `vaults` and `acls` scripts do not declare `azure_subscription_id`, so you can leave it set for all scripts.

## Run Examples

Change to the directory of the script to run, then:

```bash
terraform init
terraform apply
```

## Notes

- The `keys` script creates keys with random names. On destroy a key is soft-deleted in Azure, and purged
  as well if the vault allows it.
- The `certificates` script sets `purge_certificates_on_delete = false` in the provider block, so destroying it
  only soft-deletes the certificate in Azure. Certificate names are random, so there is no clash on a later run.
- The `secrets` script sets `purge_secrets_on_delete = false` in the provider block, so destroying it
  only soft-deletes the secret in Azure. Secret names are random, so there is no clash on a later run.
- The script directories are separate. Each one adds the same vault to CipherTrust Manager, so destroy one script
  before running the next.

## Destroy Resources

To avoid conflicts with existing resources run terraform destroy before running another script.

```bash
terraform destroy
```
Run this step even if the apply step fails.
