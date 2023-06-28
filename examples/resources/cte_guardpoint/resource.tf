
resource "ciphertrust_cte_guardpoint" "dir_auto_gp" {
    gp_type = "directory_auto"
    guard_enabled = true
    guard_paths = [ "/test1", "/test2"]
    policy_id = "test1" 
    client_id = "hostname"
}
resource "ciphertrust_cte_guardpoint" "dir_man_gp" {
    gp_type = "directory_manual"
    guard_enabled = true
    guard_paths = [ "/test3", "/test4"]
    policy_id = "test1" 
    client_id = "hostname"
}
resource "ciphertrust_cte_guardpoint" "raw_dev_gp" {
    gp_type = "rawdevice_auto"
    guard_enabled = true
    guard_paths = [ "/dev/sdb"]
    policy_id = "test1" 
    client_id = "hostname"
}
resource "ciphertrust_cte_guardpoint" "dir_ldt_auto_gp" {
    gp_type = "directory_auto"
    guard_enabled = true
    guard_paths = [ "/test5"]
    policy_id = "API_LDT_Policy1" 
    client_id = "hostname"
}
resource "ciphertrust_cte_guardpoint" "idt_auto_gp" {
    gp_type = "rawdevice_auto"
    guard_enabled = true
    guard_paths = [ "/dev/sdc"]
    policy_id = "Test_IDT" 
    client_id = "hostname"
    is_idt_capable_device =  true
}