resource "ciphertrust_smb_connection" "SmbConnection" {
        name = "Unique smb connection name."
        description = "Description about the connection."
        password = "Password for SMB share."
        username = "Username for accessing SMB share."
}