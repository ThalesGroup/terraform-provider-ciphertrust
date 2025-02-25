# Google Cloud Connection Data Source

This example demonstrates how the ciphertrust_azure_connection_list data source can be used.


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

## Configure Azure connection data source

### Edit the azure connection data source in main.tf

```bash
# Data source for retrieving azure connection details
data "ciphertrust_azure_connection_list" "example_azure_connection" {
  # Filters to narrow down the Azure connections
  filters = {
    # The unique ID of the Azure connection to fetch
    id = "7a844b20-8f63-4608-86a9-d349daf1e32c"
  }
  # Similarly can provide 'name', 'labels' etc to fetch the existing azure connection
  # example for fetching en existing azure connection with labels
  # filters = {
  #   labels = "key=value"
  # }
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