# List rotations for a key sorted by rotation date, newest first.
data "ciphertrust_aws_key_rotation_list" "sorted" {
  key_id = "77b4acd3-80e4-4270-81b5-11bb13b8053a"
  filters = {
    sort = "-RotationDate"
  }
}

# List all on-demand rotations with active key material for a key.
data "ciphertrust_aws_key_rotation_list" "on_demand_active" {
  key_id = "77b4acd3-80e4-4270-81b5-11bb13b8053a"
  filters = {
    RotationType     = "ON_DEMAND"
    KeyMaterialState = "Active"
    limit            = "-1"
  }
}
