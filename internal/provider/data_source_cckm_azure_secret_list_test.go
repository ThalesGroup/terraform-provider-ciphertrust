package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const azureSecretListSecret = "ciphertrust_azure_secret.list_secret"

// azureSecretListCase is one ciphertrust_azure_secret_list data source. Filter values are HCL expressions.
// Every case also filters on the unique secret name with limit -1. match says whether the secret is expected.
type azureSecretListCase struct {
	name    string
	filters [][2]string
	match   bool
}

func azureSecretListCases() []azureSecretListCase {
	s := func(attr string) string { return azureSecretListSecret + "." + attr }
	return []azureSecretListCase{
		{"name_only", nil, true},
		{"id", [][2]string{{"id", s("id")}}, true},
		{"key_vault_id", [][2]string{{"key_vault_id", s("vault_id")}}, true},
		{"region", [][2]string{{"region", s("region")}}, true},
		{"status", [][2]string{{"status", s("status")}}, true},
		{"secret_id", [][2]string{{"secret_id", s("azure_params.secret_id")}}, true},
		{"backup", [][2]string{{"backup", s("backup")}}, true},
		{"enabled_true", [][2]string{{"enabled", `"true"`}}, true},
		{"gone_false", [][2]string{{"gone", `"false"`}}, true},
		{"deleted_in_azure_false", [][2]string{{"deleted_in_azure", `"false"`}}, true},
		{"tags", [][2]string{{"tags", `jsonencode({ purpose = "secret-list" })`}}, true},
		{"version_latest", [][2]string{{"version", `"-1"`}}, true},
		{"sorted", [][2]string{{"sort", `"-createdAt"`}}, true},
		{"skip_0", [][2]string{{"skip", `"0"`}}, true},
		{"skip_1", [][2]string{{"skip", `"1"`}}, false},
		{"enabled_false", [][2]string{{"enabled", `"false"`}}, false},
		{"gone_true", [][2]string{{"gone", `"true"`}}, false},
		{"key_vault_no_match", [][2]string{{"key_vault", `"tf-no-such-vault"`}}, false},
		{"tags_no_match", [][2]string{{"tags", `jsonencode({ purpose = "tf-no-such-tag" })`}}, false},
	}
}

// TestCckmAzureDataSourceSecretList creates a secret and runs the ciphertrust_azure_secret_list filter cases
// against it. It is skipped when the Azure environment variables are not set.
func TestCckmAzureDataSourceSecretList(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureDataSourceSecretList")
	}

	secretName := "tf-list-" + uuid.NewString()[:8]
	secretConfig := fmt.Sprintf(`
	resource "ciphertrust_azure_secret" "list_secret" {
		vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
		name     = %q
		azure_params = {
			value = "tf-list-value"
			tags  = { purpose = "secret-list" }
		}
	}`, secretName)

	cases := azureSecretListCases()
	var sb strings.Builder
	for _, c := range cases {
		sb.WriteString(fmt.Sprintf("\n\tdata \"ciphertrust_azure_secret_list\" \"f_%s\" {\n\t\tdepends_on = [%s]\n\t\tfilters = {\n", c.name, azureSecretListSecret))
		sb.WriteString(fmt.Sprintf("\t\t\tsecret_name = %q\n\t\t\tlimit       = \"-1\"\n", secretName))
		for _, f := range c.filters {
			sb.WriteString(fmt.Sprintf("\t\t\t%s = %s\n", f[0], f[1]))
		}
		sb.WriteString("\t\t}\n\t}\n")
	}

	invalidFilterConfig := initConfig + `
	data "ciphertrust_azure_secret_list" "invalid" {
		filters = { not_a_filter = "x" }
	}`

	nameOnly := "data.ciphertrust_azure_secret_list.f_name_only"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig:   func() { logTestStep(t.Name(), "Step 0 invalid filter") },
				Config:      invalidFilterConfig,
				ExpectError: regexp.MustCompile(`not a supported filter`),
			},
			{
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    initConfig + secretConfig + sb.String(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(azureSecretListSecret, "name", secretName),
					resource.TestCheckResourceAttrPair(nameOnly, "secrets.0.id", azureSecretListSecret, "id"),
					resource.TestCheckResourceAttr(nameOnly, "secrets.0.name", secretName),
					func(s *terraform.State) error {
						secret, found := s.RootModule().Resources[azureSecretListSecret]
						if !found || secret.Primary.ID == "" {
							return fmt.Errorf("resource %s not found in state", azureSecretListSecret)
						}
						secretID := secret.Primary.ID
						t.Run("datasource", func(t *testing.T) {
							for _, c := range cases {
								c := c
								t.Run(c.name, func(t *testing.T) {
									addr := "data.ciphertrust_azure_secret_list.f_" + c.name
									ds, found := s.RootModule().Resources[addr]
									if !found {
										t.Errorf("%s not found in state", addr)
										return
									}
									attrs := ds.Primary.Attributes
									present := false
									for attr, v := range attrs {
										if strings.HasPrefix(attr, "secrets.") && strings.HasSuffix(attr, ".id") && v == secretID {
											present = true
										}
									}
									if present != c.match {
										t.Errorf("expected the secret present=%t, got %t, matched=%s count=%s",
											c.match, present, attrs["matched"], attrs["secrets.#"])
									}
								})
							}
						})
						return nil
					},
				),
			},
		},
	})
}
