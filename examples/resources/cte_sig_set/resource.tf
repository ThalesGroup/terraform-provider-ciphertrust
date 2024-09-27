resource "ciphertrust_cte_sig_set" "sig_set" {
        name = "SigSet1"
        description = "Test Sig set"
        type = "Application"
        source_list = ["/root/tmps","/usr/bin"]       
}