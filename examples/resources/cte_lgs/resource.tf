resource "ciphertrust_cte_ldtgroupcomms" "lgs" {
        	name= "test_lgs"
		description = "Testing ldt comm group using Terraform"
		client_list = "client1,client2" // Note : client_list must contain clients already present on  CM
}