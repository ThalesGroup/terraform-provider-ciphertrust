# Create a new cluster and join additional nodes on CipherTrust Manager

This example shows how to:
- Initialize a single-node cluster with `ciphertrust_cluster`
- Join additional nodes to that cluster with `ciphertrust_cluster_node`

These steps explain how to:
- Configure the CipherTrust Manager provider block for the initial node
- Configure the cluster resource for the initial node
- Configure the additional nodes to join

## Configure CipherTrust Manager

### Edit the provider block in main.tf

The provider always points at the initial cluster node.

```bash
provider "ciphertrust" {
  address  = "https://cm-address"
  username = "cm-username"
  password = "cm-password"
}
```

## Initialize the cluster on the initial node

Edit the cluster resource configuration in main.tf with actual values.

```bash
resource "ciphertrust_cluster" "cluster_info" {
  local_node_host = "primary-cm-address"
  local_node_port = 5432
  public_address  = "primary-cm-address"
}
```

## Join additional nodes to the cluster

Edit the `additional_nodes` map and the `ciphertrust_cluster_node` resource with actual values.

```bash
locals {
  additional_nodes = {
    "node2" = {
      host           = "joining-node1-cm-address"
      public_address = "joining-node1-cm-address"
      password       = "node1-cm-password"
    }
  }
}

resource "ciphertrust_cluster_node" "nodes" {
  for_each   = local.additional_nodes
  depends_on = [ciphertrust_cluster.cluster_info]

  host           = each.value.host
  port           = 5432
  public_address = each.value.public_address

  member_host = "primary-cm-address"
  member_port = 5432

  credentials = {
    address  = each.value.host
    username = "cm-username"
    password = each.value.password
  }
}
```

`credentials.address` is required: it is the endpoint Terraform uses to connect to the joining
node, and can differ from `host` when `host` holds a private/internal address used only in the CM
API payload.

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
