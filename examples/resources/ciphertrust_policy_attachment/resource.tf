resource "ciphertrust_policy_attachments" "policyattachment" {
  policy = ciphertrust_policies.policy.id
  principal_selector = <<-EOT
    {
      "groups" : ["admin"]
    }
  EOT
}