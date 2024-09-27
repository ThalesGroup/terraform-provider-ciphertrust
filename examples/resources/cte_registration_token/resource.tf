resource "ciphertrust_cte_registration_token" "reg_token" {
        name_prefix =     "name"
        lifetime = "10h"
        max_clients = 100

}