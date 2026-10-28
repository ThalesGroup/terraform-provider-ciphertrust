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
	azureCertListV1 = "ciphertrust_azure_certificate.native_v1"
	azureCertListV2 = "ciphertrust_azure_certificate.native_v2"
)

// azureCertListVersionCase is one ciphertrust_azure_certificate_list data source and the versions of the
// test certificate it is expected to return. Filter values are HCL expressions, so a reference to one of
// the certificate resources or a quoted string literal.
type azureCertListVersionCase struct {
	name    string
	filters [][2]string
	// expect is one of:
	//   "both"    - version 1 and version 2 are returned
	//   "v1"      - version 1 is returned, version 2 is not
	//   "v2"      - version 2 is returned, version 1 is not
	//   "neither" - neither version is returned (other certificates may be)
	//   "none"    - no results at all
	expect string
	// exact requires the entry count to equal the number of expected versions. Use it only when the filters
	// cannot match certificates from other tests.
	exact bool
}

// azureCertListVersionCases returns the filter cases for the two versions of the test certificate.
// Booleans and integers are strings because the filters attribute is a map of strings.
func azureCertListVersionCases() []azureCertListVersionCase {
	v1 := func(attr string) string { return azureCertListV1 + "." + attr }
	v2 := func(attr string) string { return azureCertListV2 + "." + attr }
	all := [2]string{"limit", `"-1"`}
	vault := [2]string{"key_vault_id", v1("vault_id")}
	name := [2]string{"cert_name", v1("name")}
	return []azureCertListVersionCase{
		// A name returns every version of the certificate.
		{"name_and_vault", [][2]string{name, vault, all}, "both", true},
		{"name_only", [][2]string{name, all}, "both", true},
		{"name_and_key_vault", [][2]string{name, {"key_vault", v1("vault_name")}, all}, "both", true},
		// Only the latest version.
		{"name_latest_version", [][2]string{name, vault, {"version", `"-1"`}, all}, "v2", true},
		// A single version.
		{"id_v1", [][2]string{{"id", v1("id")}}, "v1", true},
		{"id_v2", [][2]string{{"id", v2("id")}}, "v2", true},
		{"cid_v1", [][2]string{{"cid", v1("cid")}}, "v1", true},
		{"cid_v2", [][2]string{{"cid", v2("cid")}}, "v2", true},
		{"kid_v1", [][2]string{{"kid", v1("kid")}}, "v1", true},
		{"kid_v2", [][2]string{{"kid", v2("kid")}}, "v2", true},
		{"sid_v1", [][2]string{{"sid", v1("sid")}}, "v1", true},
		{"sid_v2", [][2]string{{"sid", v2("sid")}}, "v2", true},
		{"version_v1", [][2]string{name, vault, {"version", v1("version")}, all}, "v1", true},
		{"version_v2", [][2]string{name, vault, {"version", v2("version")}, all}, "v2", true},
		// A backup covers every version of the certificate, so both versions share the same backup value.
		// Version 1 is read before version 2 exists, so its state can hold an older backup. Use version 2.
		{"backup", [][2]string{{"backup", v2("backup")}}, "both", true},
		// Shared attributes. The vault may hold other certificates, so both versions only need to be present.
		{"key_vault_id", [][2]string{vault, all}, "both", false},
		{"region", [][2]string{{"region", v1("region")}, vault, all}, "both", false},
		{"cloud_name", [][2]string{{"cloud_name", v1("cloud_name")}, vault, all}, "both", false},
		{"status", [][2]string{{"status", v1("status")}, vault, all}, "both", false},
		{"cert_source", [][2]string{{"cert_source", v1("cert_source")}, vault, all}, "both", false},
		{"cert_material_origin", [][2]string{{"cert_material_origin", v1("cert_material_origin")}, vault, all}, "both", false},
		{"enabled_true", [][2]string{{"enabled", `"true"`}, vault, all}, "both", false},
		{"gone_false", [][2]string{{"gone", `"false"`}, vault, all}, "both", false},
		{"deleted_in_azure_false", [][2]string{{"deleted_in_azure", `"false"`}, vault, all}, "both", false},
		{"soft_deleted_in_azure_false", [][2]string{{"soft_deleted_in_azure", `"false"`}, vault, all}, "both", false},
		// CCKM matches the algorithm case-sensitively, so the data source sends the lower and upper case forms
		// of the value. Both versions are created from a policy with kty RSA, so they match whichever case is given.
		{"algorithm", [][2]string{{"algorithm", `"RSA"`}, vault, all}, "both", false},
		{"algorithm_lower", [][2]string{{"algorithm", `"rsa"`}, vault, all}, "both", false},
		{"sorted", [][2]string{{"sort", `"-createdAt"`}, vault, all}, "both", false},
		// Neither version matches.
		{"soft_deleted_in_azure_true", [][2]string{{"soft_deleted_in_azure", `"true"`}, vault, all}, "neither", false},
		{"enabled_false", [][2]string{{"enabled", `"false"`}, vault, all}, "neither", false},
		{"name_wrong_vault", [][2]string{name, {"key_vault", `"tf-no-such-vault"`}}, "none", false},
		{"no_such_name", [][2]string{{"cert_name", `"tf-no-such-certificate"`}}, "none", false},
		{"no_such_backup", [][2]string{{"backup", `"tf-no-such-backup"`}}, "none", false},
		{"algorithm_no_match", [][2]string{name, {"algorithm", `"tf-no-such-algorithm"`}}, "none", false},
	}
}

// azureCertListVersionConfig returns one data source block per case.
func azureCertListVersionConfig(cases []azureCertListVersionCase) string {
	var sb strings.Builder
	for _, c := range cases {
		sb.WriteString(fmt.Sprintf("\n\tdata \"ciphertrust_azure_certificate_list\" \"f_%s\" {\n\t\tdepends_on = [%s, %s]\n\t\tfilters = {\n", c.name, azureCertListV1, azureCertListV2))
		for _, f := range c.filters {
			sb.WriteString(fmt.Sprintf("\t\t\t%s = %s\n", f[0], f[1]))
		}
		sb.WriteString("\t\t}\n\t}\n")
	}
	return sb.String()
}

// azureCertListVersionChecks checks each data source case against the two certificate versions.
//
// Each case runs as a subtest (datasource/<case name>) from inside the step check, because the certificates
// and their vault are destroyed when resource.Test finishes. The subtests run in sequence and must not be
// parallel. A failed case is reported with t.Errorf so the remaining cases and the destroy still run.
func azureCertListVersionChecks(t *testing.T, cases []azureCertListVersionCase) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		r1, ok := s.RootModule().Resources[azureCertListV1]
		if !ok {
			return fmt.Errorf("resource %s not found in state", azureCertListV1)
		}
		r2, ok := s.RootModule().Resources[azureCertListV2]
		if !ok {
			return fmt.Errorf("resource %s not found in state", azureCertListV2)
		}
		id1, id2 := r1.Primary.ID, r2.Primary.ID
		if id1 == "" || id2 == "" || id1 == id2 {
			return fmt.Errorf("expected two different certificate ids, got %q and %q", id1, id2)
		}
		t.Run("datasource", func(t *testing.T) {
			for _, c := range cases {
				c := c
				t.Run(c.name, func(t *testing.T) {
					addr := "data.ciphertrust_azure_certificate_list.f_" + c.name
					ds, ok := s.RootModule().Resources[addr]
					if !ok {
						t.Errorf("%s not found in state", addr)
						return
					}
					a := ds.Primary.Attributes
					matched := a["matched"]
					count := a["certificates.#"]
					found1, found2 := false, false
					for k, v := range a {
						if strings.HasPrefix(k, "certificates.") && strings.HasSuffix(k, ".id") {
							if v == id1 {
								found1 = true
							}
							if v == id2 {
								found2 = true
							}
						}
					}
					want1, want2, wantCount := false, false, ""
					switch c.expect {
					case "both":
						want1, want2, wantCount = true, true, "2"
					case "v1":
						want1, wantCount = true, "1"
					case "v2":
						want2, wantCount = true, "1"
					case "none":
						wantCount = "0"
					}
					if found1 != want1 || found2 != want2 {
						t.Errorf("expected version 1 present=%t and version 2 present=%t, got %t and %t, matched=%s count=%s",
							want1, want2, found1, found2, matched, count)
					}
					if c.expect == "none" && (matched != "0" || count != "0") {
						t.Errorf("expected no results, matched=%s count=%s", matched, count)
					}
					if c.exact && (matched != wantCount || count != wantCount) {
						t.Errorf("expected %s results, matched=%s count=%s", wantCount, matched, count)
					}
				})
			}
		})
		return nil
	}
}

// azureCertListNativeResource returns a native certificate resource in the nonpurgeable vault. Every call with
// the same name creates another version of that certificate.
func azureCertListNativeResource(resourceName, dependsOn, certName, purpose string) string {
	deps := ""
	if dependsOn != "" {
		deps = "depends_on = [" + dependsOn + "]\n\t\t"
	}
	return fmt.Sprintf(`
	resource "ciphertrust_azure_certificate" %q {
		%[5]svault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
		name     = %[2]q
		azure_params = {
			tags = { purpose = %[3]q }
			policy = {
				issuer = { name = "Self" }
				key_props = {
					kty        = "RSA"
					key_size   = 2048
					exportable = true
					reuse_key  = false
				}
				x509_props = {
					subject         = %[4]q
					validity_months = 12
				}
			}
		}
	}`, resourceName, certName, purpose, "CN="+certName, deps)
}

// TestCckmAzureDataSourceCertificateList creates two native versions of one certificate name in the
// nonpurgeable vault and runs the ciphertrust_azure_certificate_list filter cases against them. Filters that
// identify a version return one certificate, filters on the name return both versions.
func TestCckmAzureDataSourceCertificateList(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureDataSourceCertificateList")
	}

	name := "tf-list-" + uuid.New().String()[:8]
	// Version 2 is created after version 1 and has the same name.
	createConfig := azureCertListNativeResource("native_v1", "", name, "list-v1") +
		azureCertListNativeResource("native_v2", "ciphertrust_azure_certificate.native_v1", name, "list-v2")

	// The nonpurgeable vault cannot purge, so destroy soft-deletes the certificates.
	build := func(extra string) string {
		return azureProviderCertSettingsConfig(initConfig+createConfig+extra, false, true)
	}
	cases := azureCertListVersionCases()
	invalidFilterConfig := build(`
	data "ciphertrust_azure_certificate_list" "invalid" {
		filters = { not_a_filter = "x" }
	}`)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 0: an unsupported filter key is rejected at plan time.
				Config:      invalidFilterConfig,
				ExpectError: regexp.MustCompile(`not a supported filter`),
			},
			{
				// Step 1: create two versions of the certificate and run every filter case.
				Config: build(azureCertListVersionConfig(cases)),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(azureCertListV1, "name", name),
					resource.TestCheckResourceAttr(azureCertListV2, "name", name),
					resource.TestCheckResourceAttr(azureCertListV1, "status", "AVAILABLE"),
					resource.TestCheckResourceAttr(azureCertListV2, "status", "AVAILABLE"),
					resource.TestCheckResourceAttrPair(azureCertListV1, "vault_id", azureCertListV2, "vault_id"),
					func(s *terraform.State) error {
						v1 := s.RootModule().Resources[azureCertListV1].Primary.Attributes["version"]
						v2 := s.RootModule().Resources[azureCertListV2].Primary.Attributes["version"]
						if v1 == "" || v1 == v2 {
							return fmt.Errorf("expected different Azure versions, got %q and %q", v1, v2)
						}
						return nil
					},
					azureCertListVersionChecks(t, cases),
				),
			},
		},
	})
}
