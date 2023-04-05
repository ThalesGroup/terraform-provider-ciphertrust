# Get the GCP connection data using the connection name
data "ciphertrust_gcp_connection" "by_connection_name" {
  name  = "connection-name"
}
