resource "ciphertrust_cte_resourcegroup" "rg" {
                name="TestResourceSet1"
                description = "test111"
                type = "Directory"
                resources {
                directory = "/home/testUser1"
                file = "*"
                include_subfolders = true
                }
}