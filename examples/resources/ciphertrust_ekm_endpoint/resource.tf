# A Google Cloud (GCP) connection must exist to create EKM endpoints.

# Create an EKM endpoint with minimum parameters
resource "ciphertrust_ekm_endpoint" "ekm_endpoint" {
  depends_on = [
    ciphertrust_gcp_connection.connection,
  ]
  name             = "endpoint-name"
  key_uri_hostname = "terraform.example.com"
  policy {
    clients = ["abc@google.com"]
  }
}

# Create an EKM endpoint with an asymmetric key
resource "ciphertrust_ekm_endpoint" "ekm_endpoint" {
  depends_on = [
    ciphertrust_gcp_connection.connection,
  ]
  name             = "endpoint-name"
  key_uri_hostname = "terraform.example.com"
  meta             = "some information to store with endpoint"
  policy {
    clients                = ["abc@google.com", "efg@google.com"]
    justification_required = true
    justification_reason   = ["CUSTOMER_INITIATED_SUPPORT", "MODIFIED_CUSTOMER_INITIATED_ACCESS"]
  }
  key_type  = "asymmetric"
  algorithm = "EC_SIGN_P256_SHA256"
}

# Create a UDE EKM endpoint
resource "ciphertrust_ekm_endpoint" "ekm_endpoint" {
  depends_on = [
    ciphertrust_gcp_connection.connection,
  ]
  name                    = "endpoint-name"
  key_uri_hostname        = "terraform.example.com"
  cvm_required_for_unwrap = true
  cvm_required_for_wrap   = true
  endpoint_type           = "ekm-ude"
  meta                    = "some information to store with endpoint"
  policy {
    clients                    = ["abc@google.com", "efg@google.com"]
    justification_required     = true
    justification_reason       = ["CUSTOMER_INITIATED_SUPPORT", "MODIFIED_CUSTOMER_INITIATED_ACCESS"]
    attestation_zones          = ["zone-a", "zone-b"]
    attestation_project_ids    = ["project-a", "project-b"]
    attestation_instance_names = ["instance-a", "instance-b"]
  }
}
