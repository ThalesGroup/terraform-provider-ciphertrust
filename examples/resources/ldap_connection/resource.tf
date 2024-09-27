resource "ciphertrust_ldap_connection" "ldapConnection" {
        name = "Unique connection name."
        description = "Description about the connection."
        products = "Array of the CipherTrust products associated with the connection."
        url = "url for the connection."
}