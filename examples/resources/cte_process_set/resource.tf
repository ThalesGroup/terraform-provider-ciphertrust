resource "resource "ciphertrust_cte_process_set" "process_set" {
    name = "process_set"
    description = "Process set test"
    processes {
            directory = "/root/tmp"
            file = "*"
            signature = "signature_set id"
        }
}