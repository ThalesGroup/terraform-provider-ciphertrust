# Terraform Configuration for Adding Nodes to an Existing CipherTrust Manager Cluster

terraform {
  required_providers {
    ciphertrust = {
      source  = "ThalesGroup/CipherTrust"
      version = "1.0.0-pre3"
    }
  }
}

# Configure the provider to point to an existing cluster member
provider "ciphertrust" {
  address  = "https://10.10.10.11"
  username = "admin"
  password = "ChangeMe101!"
}

# Example 1: Add a single node to an existing cluster (On-Premises / Single Network)
# ===================================================================================
resource "ciphertrust_cluster_node" "node3" {
  # host: Internal address sent in CM API payloads (CSR, join request).
  # Must be reachable by other cluster members for internal cluster communication.
  host = "10.10.10.13"
  port = 5432

  # public_address: Address for external connectors/applications.
  # Can be same as host, or a public IP/FQDN/load balancer.
  public_address = "10.10.10.13"

  member_host = "10.10.10.11"
  member_port = 5432

  credentials = {
    # address: The endpoint Terraform uses to connect to the joining node.
    # On-premises (single network): same as host is fine.
    address  = "10.10.10.13"
    username = "admin"
    password = "ChangeMe103!"
  }
}

# Example 2: Add node with custom credentials and domain
# =======================================================
resource "ciphertrust_cluster_node" "node4" {
  host           = "10.10.10.14"
  port           = 5432
  public_address = "node4.example.com"

  member_host = "10.10.10.11"
  member_port = 5432

  credentials = {
    address     = "10.10.10.14"
    username    = "clusteradmin"
    password    = "ChangeMe104!"
    domain      = "root"
    auth_domain = "local"
  }
}

# Example 3: AWS EC2 (Terraform running outside VPC)
# ====================================================
# When running Terraform outside the VPC, the joining node cannot be reached
# via its private IP. Use the FQDN in credentials.address so Terraform connects
# via the public endpoint, while host holds the private IP that CM uses internally.
#
# Why FQDN and not public IP for credentials.address:
#   EC2 instances cannot reach their own public IPs (AWS hairpin NAT).
#   FQDNs resolve to private IPs from inside the VPC and public IPs from outside.
resource "ciphertrust_cluster_node" "aws_node_external_terraform" {
  # host: Private IP — sent in CM API payloads for internal cluster routing.
  host = "172.30.100.184"
  port = 5432

  # public_address: Public IP for external connectors.
  public_address = "3.232.96.8"

  member_host = "ec2-3-239-247-150.compute-1.amazonaws.com"
  member_port = 5432

  credentials = {
    # address: FQDN so Terraform (running outside VPC) can reach the joining node.
    address  = "ec2-3-232-96-8.compute-1.amazonaws.com"
    username = "admin"
    password = "Ssl12345#"
  }
}

# Example 3b: AWS EC2 (Terraform running inside same VPC)
# ========================================================
# When Terraform runs inside the same VPC, use private IPs everywhere.
resource "ciphertrust_cluster_node" "aws_node_internal_terraform" {
  host           = "172.30.100.184"
  port           = 5432
  public_address = "44.200.204.237"

  member_host = "172.30.100.183"
  member_port = 5432

  credentials = {
    address  = "172.30.100.184"
    username = "admin"
    password = "Ssl12345#"
  }
}

# Example 4: Adding node to a cluster created in same configuration
# ==================================================================
resource "ciphertrust_cluster" "main" {
  local_node_host = "10.10.10.11"
  local_node_port = 5432
  public_address  = "10.10.10.11"
}

resource "ciphertrust_cluster_node" "node2" {
  depends_on = [ciphertrust_cluster.main]

  host           = "10.10.10.12"
  port           = 5432
  public_address = "10.10.10.12"

  member_host = "10.10.10.11"
  member_port = 5432

  credentials = {
    address  = "10.10.10.12"
    username = "admin"
    password = "ChangeMe102!"
  }
}

# Outputs
output "node_id" {
  description = "CipherTrust Manager node ID"
  value       = ciphertrust_cluster_node.node3.node_id
}

output "cluster_size" {
  description = "Total nodes in cluster after adding this node"
  value       = ciphertrust_cluster_node.node3.node_count
}

output "status" {
  description = "Cluster status after node join"
  value       = ciphertrust_cluster_node.node3.status_description
}

# Notes:
# ======
#
# host vs credentials.address:
# ----------------------------
# - host: sent in CM API payloads (CSR generation, join request).
#         Use the private/internal address that cluster members use to talk to each other.
# - credentials.address: the endpoint Terraform connects to for API calls to the joining node.
#         Use a publicly-reachable address or FQDN when Terraform runs outside the node's network.
#
# Removing a Node:
# ----------------
# - Running terraform destroy on this resource will:
#   1. Remove the node from the cluster
#   2. Clear cluster config on the removed node
#
# Member Host Selection:
# ----------------------
# - member_host can be ANY node that is already in the cluster.
# - Does not have to be the original/first node.
#
# Sequential Joins:
# -----------------
# - When using for_each to add multiple nodes, they join one at a time automatically.
# - The provider holds a lock until each join fully completes (joining node ready +
#   cluster member confirmed stable) before starting the next join.
