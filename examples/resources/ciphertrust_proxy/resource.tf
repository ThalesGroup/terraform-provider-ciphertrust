resource "ciphertrust_proxy" "proxie" {
  http_proxy = "user01:test12345@10.171.18.190:8080"
  https_proxy = "user02:Test12345@10.171.18.190:8081"
  no_proxy = ["127.0.0.1", "localhost"]
}