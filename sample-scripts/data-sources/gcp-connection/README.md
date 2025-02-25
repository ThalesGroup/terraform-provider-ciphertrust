# Google Cloud Connection Data Source

This example demonstrates how the ciphertrust_gcp_connection_list data source can be used.


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

## Configure GCP connection data source

### Edit the gcp connection data source in main.tf

```bash
# Data source for retrieving GCP connection details
data "ciphertrust_gcp_connection_list" "example_gcp_connection" {
  # Filters to narrow down the GCP connections
  filters = {
    # The unique ID of the GCP connection to fetch
    id = "60f04cb1-4a48-4786-8965-39f2031518c4"
  }
  # Similarly can provide 'name', 'labels' etc to fetch the existing GCP connection
  # example for fetching en existing gcp connection with labels
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
