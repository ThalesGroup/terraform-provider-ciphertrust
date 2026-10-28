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

const (
	azureKeyListKey      = "ciphertrust_azure_key.list_key"
	azureKeyListRotation = "ciphertrust_scheduler.rotation_scheduler"
	azureKeyListBackup   = "ciphertrust_scheduler.backup_scheduler"
)

// azureKeyListCase is one ciphertrust_azure_key_list data source. Filter values are HCL expressions, so a
// reference to the test key or a quoted string literal. Every case also filters on the unique name of the
// test key with limit -1, so that other keys in the vault cannot hide or add results. match says whether the
// test key is expected in the results.
type azureKeyListCase struct {
	name    string
	filters [][2]string
	match   bool
}

// azureKeyListCases returns the filter cases for the EC test key. Booleans and integers are strings
// because the filters attribute is a map of strings.
//
// Not covered here: key_size and external_key_id (an EC key has neither). The version filter and the
// RSA side of the algorithm filter are covered by TestCckmAzureKeyUploadAndRunScheduler.
func azureKeyListCases() []azureKeyListCase {
	k := func(attr string) string { return azureKeyListKey + "." + attr }
	return []azureKeyListCase{
		{"name_only", nil, true},
		{"id", [][2]string{{"id", k("id")}}, true},
		{"key_vault_id", [][2]string{{"key_vault_id", k("vault_id")}}, true},
		{"key_vault", [][2]string{{"key_vault", k("vault_name")}}, true},
		{"cloud_name", [][2]string{{"cloud_name", k("cloud_name")}}, true},
		{"region", [][2]string{{"region", k("region")}}, true},
		{"status", [][2]string{{"status", k("status")}}, true},
		{"kid", [][2]string{{"kid", k("azure_params.key.kid")}}, true},
		{"key_material_origin", [][2]string{{"key_material_origin", k("key_material_origin")}}, true},
		{"backup", [][2]string{{"backup", k("backup")}}, true},
		{"job_config_id", [][2]string{{"job_config_id", azureKeyListRotation + ".id"}}, true},
		{"backup_job_config_id", [][2]string{{"backup_job_config_id", azureKeyListBackup + ".id"}}, true},
		{"rotation_job_enabled_true", [][2]string{{"rotation_job_enabled", `"true"`}}, true},
		{"enabled_true", [][2]string{{"enabled", `"true"`}}, true},
		{"gone_false", [][2]string{{"gone", `"false"`}}, true},
		{"deleted_in_azure_false", [][2]string{{"deleted_in_azure", `"false"`}}, true},
		{"managed", [][2]string{{"managed", k("managed")}}, true},
		{"tags", [][2]string{{"tags", `jsonencode({ purpose = "key-list" })`}}, true},
		{"version_latest", [][2]string{{"version", `"-1"`}}, true},
		{"sorted", [][2]string{{"sort", `"-createdAt"`}}, true},
		{"skip_0", [][2]string{{"skip", `"0"`}}, true},
		// CCKM matches the algorithm and the curve case-sensitively, so the data source sends the lower and
		// upper case forms of the value. The key matches whichever case is given.
		{"algorithm_upper", [][2]string{{"algorithm", `"EC"`}}, true},
		{"algorithm_lower", [][2]string{{"algorithm", `"ec"`}}, true},
		{"curve_upper", [][2]string{{"curve", `"P-256"`}}, true},
		{"curve_lower", [][2]string{{"curve", `"p-256"`}}, true},
		// The key does not match.
		{"skip_1", [][2]string{{"skip", `"1"`}}, false},
		{"enabled_false", [][2]string{{"enabled", `"false"`}}, false},
		{"gone_true", [][2]string{{"gone", `"true"`}}, false},
		{"rotation_job_enabled_false", [][2]string{{"rotation_job_enabled", `"false"`}}, false},
		{"algorithm_rsa", [][2]string{{"algorithm", `"RSA"`}}, false},
		{"curve_p384", [][2]string{{"curve", `"P-384"`}}, false},
		{"key_vault_no_match", [][2]string{{"key_vault", `"tf-no-such-vault"`}}, false},
		{"job_config_id_no_match", [][2]string{{"job_config_id", `"00000000-0000-0000-0000-000000000000"`}}, false},
		{"backup_job_config_id_no_match", [][2]string{{"backup_job_config_id", `"00000000-0000-0000-0000-000000000000"`}}, false},
		{"tags_no_match", [][2]string{{"tags", `jsonencode({ purpose = "tf-no-such-tag" })`}}, false},
	}
}

// TestCckmAzureDataSourceKeyList creates an EC key, attaches a rotation scheduler and a backup scheduler in an
// update (they cannot be set on create) and runs the ciphertrust_azure_key_list filter cases against it. The
// backup value changes in the update, so the cases run after it. Together with the version and RSA
// algorithm data sources in TestCckmAzureKeyUploadAndRunScheduler, this covers the filters of the data source.
func TestCckmAzureDataSourceKeyList(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureDataSourceKeyList")
	}

	keyName := "tf-list-" + uuid.NewString()[:8]
	backupSchedulerName := "tf-" + uuid.NewString()[:8]
	rotationSchedulerName := "tf-" + uuid.NewString()[:8]

	// The schedulers cannot be attached when a key is created, so the key is created without them in step 1
	// and the schedulers are attached by an update in step 2.
	schedulerConfig := applyCDSPAAS(fmt.Sprintf(`
		resource "ciphertrust_scheduler" "backup_scheduler" {
			name      = %q
			operation = "cckm_key_backup"
			run_at    = "0 9 * * fri"
			run_on    = "any"
			cckm_key_backup_params = {
				cloud_name = "AzureCloud"
			}
		}
		resource "ciphertrust_scheduler" "rotation_scheduler" {
			name      = %q
			operation = "cckm_key_rotation"
			run_at    = "0 9 * * fri"
			run_on    = "any"
			cckm_key_rotation_params = {
				cloud_name = "AzureCloud"
				expiration = "365d"
				expire_in  = "10d"
			}
		}`, backupSchedulerName, rotationSchedulerName))

	// keyConfig returns the EC key with the given extra attributes. Args: extra attributes.
	keyConfig := func(extra string) string {
		return fmt.Sprintf(`
		resource "ciphertrust_azure_key" "list_key" {
			vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
			name     = %q
			azure_params = {
				key = {
					kty     = "EC"
					curve   = "P-256"
					key_ops = ["sign", "verify"]
				}
				tags = { purpose = "key-list" }
			}
			%s
		}`, keyName, extra)
	}
	attachConfig := `
			enable_auto_backup = {
				job_config_id = ciphertrust_scheduler.backup_scheduler.id
			}
			enable_auto_rotation = {
				job_config_id = ciphertrust_scheduler.rotation_scheduler.id
				key_source    = "native"
				key_type      = "EC"
				ec_name       = "P-256"
			}`
	createConfig := initConfig + schedulerConfig + keyConfig("")
	updateConfig := initConfig + schedulerConfig + keyConfig(attachConfig)

	cases := azureKeyListCases()
	var sb strings.Builder
	for _, c := range cases {
		sb.WriteString(fmt.Sprintf("\n\tdata \"ciphertrust_azure_key_list\" \"f_%s\" {\n\t\tdepends_on = [%s]\n\t\tfilters = {\n", c.name, azureKeyListKey))
		sb.WriteString(fmt.Sprintf("\t\t\tkey_name = %q\n\t\t\tlimit    = \"-1\"\n", keyName))
		for _, f := range c.filters {
			sb.WriteString(fmt.Sprintf("\t\t\t%s = %s\n", f[0], f[1]))
		}
		sb.WriteString("\t\t}\n\t}\n")
	}
	casesConfig := sb.String()

	invalidFilterConfig := initConfig + `
	data "ciphertrust_azure_key_list" "invalid" {
		filters = { not_a_filter = "x" }
	}`

	nameOnly := "data.ciphertrust_azure_key_list.f_name_only"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 0: an unsupported filter key is rejected at plan time.
				PreConfig:   func() { logTestStep(t.Name(), "Step 0 invalid filter") },
				Config:      invalidFilterConfig,
				ExpectError: regexp.MustCompile(`not a supported filter`),
			},
			{
				// Step 1: create the key without the schedulers.
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    createConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(azureKeyListKey, "name", keyName),
					resource.TestCheckResourceAttr(azureKeyListKey, "azure_params.key.kty", "EC"),
					resource.TestCheckResourceAttr(azureKeyListKey, "azure_params.key.curve", "P-256"),
					resource.TestCheckNoResourceAttr(azureKeyListKey, "enable_auto_backup"),
					resource.TestCheckNoResourceAttr(azureKeyListKey, "enable_auto_rotation"),
				),
			},
			{
				// Step 2: attach the schedulers, which changes the backup value, and run every filter case.
				PreConfig: func() { logTestStep(t.Name(), "Step 2") },
				Config:    updateConfig + casesConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(azureKeyListKey, "name", keyName),
					resource.TestCheckResourceAttrPair(azureKeyListKey, "enable_auto_rotation.job_config_id", azureKeyListRotation, "id"),
					resource.TestCheckResourceAttrPair(azureKeyListKey, "enable_auto_backup.job_config_id", azureKeyListBackup, "id"),
					// The entry returned for the key carries the same values as the resource.
					resource.TestCheckResourceAttrPair(nameOnly, "keys.0.id", azureKeyListKey, "id"),
					resource.TestCheckResourceAttrPair(nameOnly, "keys.0.vault_id", azureKeyListKey, "vault_id"),
					resource.TestCheckResourceAttr(nameOnly, "keys.0.name", keyName),
					resource.TestCheckResourceAttr(nameOnly, "keys.0.kty", "EC"),
					resource.TestCheckResourceAttr(nameOnly, "keys.0.curve", "P-256"),
					// Each case runs as a subtest (datasource/<case name>) from inside the step check, because
					// the key and its vault are destroyed when resource test finishes. The subtests run in
					// sequence. A failed case is reported with t.Errorf so the other cases still run.
					func(s *terraform.State) error {
						key, found := s.RootModule().Resources[azureKeyListKey]
						if !found || key.Primary.ID == "" {
							return fmt.Errorf("resource %s not found in state", azureKeyListKey)
						}
						keyID := key.Primary.ID
						t.Run("datasource", func(t *testing.T) {
							for _, c := range cases {
								c := c
								t.Run(c.name, func(t *testing.T) {
									addr := "data.ciphertrust_azure_key_list.f_" + c.name
									ds, found := s.RootModule().Resources[addr]
									if !found {
										t.Errorf("%s not found in state", addr)
										return
									}
									attrs := ds.Primary.Attributes
									present := false
									for attr, v := range attrs {
										if strings.HasPrefix(attr, "keys.") && strings.HasSuffix(attr, ".id") && v == keyID {
											present = true
										}
									}
									if present != c.match {
										t.Errorf("expected the key present=%t, got %t, matched=%s count=%s",
											c.match, present, attrs["matched"], attrs["keys.#"])
									}
									if c.match && (attrs["matched"] != "1" || attrs["keys.#"] != "1") {
										t.Errorf("expected 1 result, matched=%s count=%s", attrs["matched"], attrs["keys.#"])
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
