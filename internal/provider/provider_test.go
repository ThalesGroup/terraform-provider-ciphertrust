package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

const (
	providerConfig = `
provider "ciphertrust" {
  address   = "%s"
  username  = "%s"
  password  = "%s"
  bootstrap = "%s"
}
`
)

var (
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"ciphertrust": providerserver.NewProtocol6WithError(New("ciphertrust")()),
	}
)
