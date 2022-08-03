resource "ciphertrust_syslog" "syslog_1" {
    host = "example.syslog.com"
    transport = "udp"
}
