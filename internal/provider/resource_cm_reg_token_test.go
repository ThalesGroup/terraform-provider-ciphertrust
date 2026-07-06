package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMRegToken(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}

output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}

resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify number of items
					//resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.reg_token", "items.#", "1"),
					// Verify first order item
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.quantity", "2"),
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.coffee.id", "1"),
					// Verify first coffee item has Computed attributes filled.
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.coffee.description", ""),
					// Verify dynamic values have any value set in the state.
					//resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "token"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "id"),
				),
			},
			// ImportState testing
			//{
			//	ResourceName:      "ciphertrust_cm_reg_token.reg_token",
			//	ImportState:       true,
			//	ImportStateVerify: true,
			// The last_updated attribute does not exist in the HashiCups
			// API, therefore there is no value for it during import.
			//	ImportStateVerifyIgnore: []string{"last_updated"},
			//},
			// Update and Read testing
			{
				Config: providerConfig + `
data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}
output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}
resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify first order item updated
					//resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "token"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func TestCipherTrust_CMRegToken_drift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  max_clients = 5
}
`,
				Check: checkStep(t, "drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "max_clients", "5"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// OOB change: update max_clients to 10; Read() must surface the drift.
				// lifetime is intentionally excluded: CM does not echo lifetime in GET
				// responses, so it cannot be used to test drift detection.
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"max_clients": 10})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_REG_TOKEN, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestCipherTrust_CMRegToken_deleteOOB(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "test-"
}
`,
				Check: checkStep(t, "deleteOOB: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					_, _ = client.DeleteByURL(context.Background(), uuid.New().String(), common.URL_REG_TOKEN+"/"+capturedID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "test-"
}
`,
				Check: checkStep(t, "deleteOOB: recreated",
					resource.TestCheckResourceAttrWith("ciphertrust_cm_reg_token.test", "id", func(val string) error {
						if val == capturedID {
							return fmt.Errorf("expected new id after OOB delete, got same id %s", val)
						}
						return nil
					}),
				),
			},
		},
	})
}

func TestCipherTrust_CMRegToken_labelCreate(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  label  = { KmipClientProfile = "default" }
  labels = { env = "test" }
}
`,
				Check: checkStep(t, "labelCreate: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "label.KmipClientProfile", "default"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.env", "test"),
				),
			},
			// Confirm no false drift on map attributes after Read() hydration.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestCipherTrust_CMRegToken_labelDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  label = { KmipClientProfile = "default" }
}
`,
				Check: checkStep(t, "labelDrift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "label.KmipClientProfile", "default"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"label": map[string]interface{}{"KmipClientProfile": "updated"}})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_REG_TOKEN, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestCipherTrust_CMRegToken_labelsDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  labels = { env = "staging" }
}
`,
				Check: checkStep(t, "labelsDrift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.env", "staging"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"labels": map[string]interface{}{"env": "production"}})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_REG_TOKEN, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestCipherTrust_CMRegToken_namePrefixDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "orig-"
}
`,
				Check: checkStep(t, "namePrefixDrift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "name_prefix", "orig-"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"name_prefix": "changed-"})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_REG_TOKEN, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
