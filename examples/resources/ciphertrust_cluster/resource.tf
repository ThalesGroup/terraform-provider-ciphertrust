# Create cluster from set of AWS EC2 instances
# // https://registry.terraform.io/providers/hashicorp/aws/latest/docs
resource "ciphertrust_cluster" "cluster" {
  dynamic "node" {
    for_each = module.ec2_instance
    content {
      host           = node.value.private_ip
      public_address = node.value.public_ip
    }
  }
}

# Create cluster from fixed instances, specify which node is to be the first member
resource "ciphertrust_cluster" "cluster" {
  node {
    original       = true
    host           = "1.1.1.1"
    public_address = "2.2.2.2"
  }
  node {
    host           = "3.3.3.3"
    public_address = "4.4.4.5"
  }
}