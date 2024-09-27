resource "ciphertrust_cte_clientgroup" "clientgroup" {
        name = "Name of  Client group"
        description = "Desc of  client group"   
        communication_enabled =   false
        password_creation_method =   "password creation type",
        profile_id = "client profile name"
        cluster_type = "cluster type"
}