package provider

import (
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"testing"
)

func TestResourceGCPConnection(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// creating an GCP connection
			{
				Config: providerConfig + `
resource "ciphertrust_gcp_connection" "gcp_connection" {
  name        = "test-gcp-connection"
  products = [
    "cckm"
  ]
  key_file    = "{\"type\":\"service_account\",\"private_key_id\":\"y437c51g956b8ab4908yb41541262a2fa3b0f84f\",\"private_key\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIICXAIBAAKBgQDnC1YYTtcpsbj6cV9M/1rOhEYWG9iNdnsMCK0AjMRtb79toU2v\\nyW0JfJR/sR2vqFMD1wJFgpayqo5GDPa8Us23I/vvyWCkatouGYO27r84y5G2h74a\\nZnnEaK7uLQ2OdGNHWcZv8gZhy7X5e6RJfKVVlYrgYtfEKv55E9dQSZrohQIDAQAB\\nAoGAbzre7P7vyQvdkPyJs+jvj6LQlw462AflPyriFvSuED2PPDk+zFU9oCaQ21Sq\\nhQmVRbD6T/qJkGRZ8FGHa6y1if6UVbUymr+0a1hIM7BbPwsG2hLXznYjXWZ8WFDb\\nQyRWTZh4Zj0Br2DtoRjQOG8CHhC7LuFx434acu12VXxN8vUCQQDtS8GRzktOWRBL\\n2l7MWCja3lkqyYR2Ns+tw79eEAYVrGsFZLu6gAMdmn53M+eO5h++Ypr7G+bazvwC\\nD1XtiN+7AkEA+UFuq04YR3lTpCN1OeJ0VKXatVMFMjAejulHF3d3tRc4pIfAjgTk\\n4M+K9y++4QtVdhsGO9sk1jwfHrRTn340vwJBAIJ25DYF9eFdllgd94Dh95ReKygb\\nI3jbKdOfi9drd+zynuSYPZ6MQypDhsSDBQzL+SfzjsIA1Sv4IRYA2H2Ag4ECQAYw\\nHKo+DxY/KddqVe+w8ohjcbGMtRVQ4oFTw0MO4Tbqs6pKAHrGHlSCcoW+drOpj16W\\nPypfP2PeLDub6HOOM4sCQGWUXaHqJzfy2nHRAkr9WJEGgEMCMlGtFuMPH/Jc7aUt\\nNXk9HfcpVO/spIVpyL7x480hq5DHn7KaGwi+Lk2W0A8=\\n-----END RSA PRIVATE KEY-----\\n\\n\",\"client_email\":\"test@some-project.iam.gserviceaccount.com\"}"
  cloud_name  = "gcp"
  description = "connection description"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }
}
`,
				// verifying the resources for id, private key id, client email, cloud name and products
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "id"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "private_key_id", "y437c51g956b8ab4908yb41541262a2fa3b0f84f"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "client_email", "test@some-project.iam.gserviceaccount.com"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "cloud_name", "gcp"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.0", "cckm"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + `
resource "ciphertrust_gcp_connection" "gcp_connection" {
  name        = "test-gcp-connection"
  products = [
    "ddc"
  ]
  key_file    = "{\"type\":\"service_account\",\"private_key_id\":\"p437c51g956b8ab4908yb41541262a2fa3b0f84f\",\"private_key\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIICXAIBAAKBgQDnC1YYTtcpsbj6cV9M/1rOhEYWG9iNdnsMCK0AjMRtb79toU2v\\nyW0JfJR/sR2vqFMD1wJFgpayqo5GDPa8Us23I/vvyWCkatouGYO27r84y5G2h74a\\nZnnEaK7uLQ2OdGNHWcZv8gZhy7X5e6RJfKVVlYrgYtfEKv55E9dQSZrohQIDAQAB\\nAoGAbzre7P7vyQvdkPyJs+jvj6LQlw462AflPyriFvSuED2PPDk+zFU9oCaQ21Sq\\nhQmVRbD6T/qJkGRZ8FGHa6y1if6UVbUymr+0a1hIM7BbPwsG2hLXznYjXWZ8WFDb\\nQyRWTZh4Zj0Br2DtoRjQOG8CHhC7LuFx434acu12VXxN8vUCQQDtS8GRzktOWRBL\\n2l7MWCja3lkqyYR2Ns+tw79eEAYVrGsFZLu6gAMdmn53M+eO5h++Ypr7G+bazvwC\\nD1XtiN+7AkEA+UFuq04YR3lTpCN1OeJ0VKXatVMFMjAejulHF3d3tRc4pIfAjgTk\\n4M+K9y++4QtVdhsGO9sk1jwfHrRTn340vwJBAIJ25DYF9eFdllgd94Dh95ReKygb\\nI3jbKdOfi9drd+zynuSYPZ6MQypDhsSDBQzL+SfzjsIA1Sv4IRYA2H2Ag4ECQAYw\\nHKo+DxY/KddqVe+w8ohjcbGMtRVQ4oFTw0MO4Tbqs6pKAHrGHlSCcoW+drOpj16W\\nPypfP2PeLDub6HOOM4sCQGWUXaHqJzfy2nHRAkr9WJEGgEMCMlGtFuMPH/Jc7aUt\\nNXk9HfcpVO/spIVpyL7x480hq5DHn7KaGwi+Lk2W0A8=\\n-----END RSA PRIVATE KEY-----\\n\\n\",\"client_email\":\"test-updated@some-project.iam.gserviceaccount.com\"}"
  description = "updated connection description"
}
				`,
				// verifying the updated field private key id, client email, description and products
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "private_key_id", "p437c51g956b8ab4908yb41541262a2fa3b0f84f"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "client_email", "test-updated@some-project.iam.gserviceaccount.com"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "description", "updated connection description"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.0", "ddc"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
