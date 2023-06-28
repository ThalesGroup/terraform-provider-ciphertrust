resource "ciphertrust_cte_client" "client" {
    name = "hostname"
    password_creation_method = "GENERATE"
    password="sample_password"
    description = "Temp host for testing."
    registration_allowed = true
    communication_enabled = true 
}