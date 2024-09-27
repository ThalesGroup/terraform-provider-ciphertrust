resource "ciphertrust_oidc_connection" "OIDCConnection" {
        name = "Unique connection name."
        description = "Description about the connection."
        products = "Array of the CipherTrust products associated with the connection."
        client_id = "clientID for the connection."
        client_secret = "Client Secret of the OIDC connection."
        url = "url for the connection."
}