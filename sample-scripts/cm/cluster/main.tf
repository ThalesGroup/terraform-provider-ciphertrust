terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

# The provider points to the initial cluster node.
provider "ciphertrust" {
  address  = "https://10.10.10.11"
  username = "admin"
  password = "ChangeMe101!"
}

# Step 1: initialize the cluster on the main node. This creates a
# single-node cluster that additional nodes can join.
resource "ciphertrust_cluster" "cluster_info" {
  local_node_host = "10.10.10.11" # hostname/IP of this node
  local_node_port = 5432          # defaults to 5432
  public_address  = "10.10.10.11" # public IP/FQDN for remote connectors, updatable
}

# Step 2: define additional nodes to join the cluster.
locals {
  additional_nodes = {
    "node2" = {
      host           = "10.10.10.12"
      public_address = "10.10.10.12"
      password       = "ChangeMe102!"
    }
    "node3" = {
      host           = "10.10.10.13"
      public_address = "10.10.10.13"
      password       = "ChangeMe103!"
    }
  }
}

# Step 3: add the additional nodes to the cluster. depends_on ensures the
# cluster exists before joining nodes, and each join waits for the previous
# one to complete.
resource "ciphertrust_cluster_node" "nodes" {
  for_each   = local.additional_nodes
  depends_on = [ciphertrust_cluster.cluster_info]

  host           = each.value.host
  port           = 5432
  public_address = each.value.public_address # updatable

  # member_host: an existing cluster member to sign the CSR and coordinate
  # the join. Can be any node already in the cluster, not necessarily the
  # first one.
  member_host = "10.10.10.11"
  member_port = 5432

  # Credentials for the new node. address is the endpoint Terraform uses to
  # connect to the joining node; it can differ from host when host holds a
  # private/internal address used only in the CM API payload.
  credentials = {
    address  = each.value.host
    username = "admin"
    password = each.value.password
  }
}

output "cluster_id" {
  value = ciphertrust_cluster.cluster_info.id
}

output "cluster_node_count" {
  value = ciphertrust_cluster.cluster_info.node_count
}

output "additional_node_ids" {
  value = { for k, v in ciphertrust_cluster_node.nodes : k => v.node_id }
}
