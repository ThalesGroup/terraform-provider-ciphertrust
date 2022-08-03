resource "ciphertrust_log_forwarder" "log_forwarder_1" {
    connection_id = "61dfa3f4-1c14-4827-9dd4-c22988ce10d6"
    name = "es_test"
    type = "elasticsearch"
    elasticsearch_params {
        indices {
            activity_kmip = "index_kmip"
            activity_nae = "index_nae"
            server_audit_records = "index_server"
            client_audit_records = "index_client"
        }
    }
}
