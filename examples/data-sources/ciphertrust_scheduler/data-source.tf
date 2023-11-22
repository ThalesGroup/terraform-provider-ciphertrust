# Retrieve details using the scheduler's name
data "ciphertrust_scheduler" "scheduler_by_name" {
  name = "Rotation Scheduler"
}

# Retrieve details using the ID of the scheduler
data "ciphertrust_aws_key" "scheduler_by_id" {
  id = "77b4acd3-80e4-4270-81b5-11bb13b8053a"
}
