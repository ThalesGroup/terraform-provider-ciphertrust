# Perform an on-demand rotation of an AWS native symmetric key.
# Each time trigger changes, one rotation is requested.
#
# NOTE: key_id cannot be changed after the resource is created.
# To target a different key, remove this resource and create a new one.
#
# NOTE: Removing this resource from config is a no-op - the rotation that
# was already performed in AWS is not reversed or undone.
resource "ciphertrust_aws_key_rotation" "rotate" {
  key_id  = ciphertrust_aws_key.aws_key.id
  trigger = "2026-06-01"
}
