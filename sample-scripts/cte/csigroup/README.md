# Configure a CipherTrust Transparent Encryption CSI Storage Group on CipherTrust Manager

This example shows how to:
- Create a CipherTrust CSI Storage Group on CipherTrust Manager to protect Persistent Volume in a Kubernetes envrionment

These steps explain how to:
- Configure CipherTrust Manager Provider parameters required to run the examples
- Configure CTE CSI Storage Group parameters
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

## Configure CTE CSI Storage Group parameters
Edit the CTE configuration resource in main.tf
```bash
resource "ciphertrust_cte_csigroup" "csigroup" {
    kubernetes_namespace = "default"
    kubernetes_storage_class = "tf_class"
    name = "TF_CSI_Group"
    description = "Created via TF"
}
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources
Resources must be destroyed before another sample script using the same cloud is run.

```bash
terraform destroy
```

Run this step even if the apply step fails.