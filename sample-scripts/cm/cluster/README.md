# Create a new cluster or join existing cluster on CipherTrust Manager

This example shows how to:
- Create a new cluster
- Join existing CiphereTrust Manager Nodes to the above cluster

These steps explain how to:
- Configure CipherTrust Manager Provider parameters for primary as well as the joining nodes required to run the examples
- Enable trial license if needed
- Configure parameters required to create new cluster and join other nodes to it
- Run the example


## Configure CipherTrust Manager

### Edit the cluster's primary CipherTrust Manager node provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
  domain   = "cm-domain"
  bootstrap = "no"
  alias = "primary"
}
```

### Edit a new cluster joining CipherTrust Manager node provider block in main.tf

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
  domain   = "cm-domain"
  bootstrap = "no"
  alias = "secondary"
}
```

## Enable trial license on primary node in cluster

```bash
resource "ciphertrust_trial_license" "trial_license_primary" {
	provider = ciphertrust.primary
}
```

## Enable trial license on joining node in cluster

```bash
resource "ciphertrust_trial_license" "trial_license_secondary" {
	provider = ciphertrust.secondary
}
```

## Create new cluster using node with original as true and join other nodes to the said cluster
Edit the cluster resource configuration in main.tf with actual values
```bash
resource "ciphertrust_cluster" "cluster_info" {
	provider = ciphertrust.primary
	nodes = [
		{
			host = "https://primary-cm-address"
			port = 5432
			original = true
			public_address = "https://primary-cm-address"
			credentials = {
				username = "cm-username"
				password = "cm-password"
			}
		},
		{
			host = "https://joining-node1-cm-address"
			port = 5432
			original = false
			public_address = "https://joining-node1-cm-address"
			credentials = {
				username = "cm-username"
				password = "cm-password"
			}
		}
	]
}
```

## Run the Example

```bash
terraform init
terraform apply
```

## Destroy Resources
Resources must be destroyed before another sample script using the same domain name is run.

```bash
terraform destroy
```

Run this step even if the apply step fails.