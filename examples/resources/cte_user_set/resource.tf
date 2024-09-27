resource "ciphertrust_cte_user_set" "user_set" {
        name = "UserSet1"
        description = "Test User set"
        users  {
                uname = "root1234"
                uid = 1000
                gname = "rootGroup"
                gid = 1000
                os_domain = ""
        }
        users {
                uname = "test1234"
                uid = 1234
                gname = "testGroup"
                gid = 1234
                os_domain = ""
        }
        
}