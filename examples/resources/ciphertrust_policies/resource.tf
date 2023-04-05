resource "ciphertrust_policies" "policy" {
    name    =   "policyReadKeyOnly"
    actions =   ["ReadKey"]
    allow   =   true
    effect  =   "allow"
    conditions {
        path   = "context.resource.alg"
        op     = "equals"
        values = ["aes","rsa"]
    }
}