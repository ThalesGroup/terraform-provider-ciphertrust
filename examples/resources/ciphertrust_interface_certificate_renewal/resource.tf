# Renew the TLS server certificate of a CipherTrust Manager interface.
# Each time trigger changes, a new certificate is staged as the upcoming
# certificate and then applied exactly once.
#
# NOTE: interface_name cannot be changed after the resource is created.
# To target a different interface, remove this resource and create a new one.
#
# NOTE: Removing this resource from config is a no-op - the certificate that
# was already applied on the interface is not reverted.
resource "ciphertrust_interface_certificate_renewal" "renew" {
  interface_name = ciphertrust_interface.web.name
  generate       = true
  trigger        = "2026-06-01"
}
