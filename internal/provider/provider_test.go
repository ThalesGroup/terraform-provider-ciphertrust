package provider

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// Acceptance tests run against lab / CI CipherTrust Managers whose TLS
// certificates are self-signed (often without IP SANs). With the secure-by-
// default provider, this would block tests at plan time on certificate
// verification. Set NO_SSL_VERIFY=true at package init unless the operator
// has supplied a trusted CA bundle for the test target — this propagates
// through the provider's standard env-var precedence and covers every
// inline test provider block, not just `providerConfig`. End-user defaults
// outside of `go test` are unchanged.
func init() {
	if os.Getenv("CIPHERTRUST_CA_CERT") != "" {
		return
	}
	if _, set := os.LookupEnv("NO_SSL_VERIFY"); set {
		return // honour an explicit override (including "false")
	}
	_ = os.Setenv("NO_SSL_VERIFY", "true")
}

// providerConfig is the HCL provider block injected at the front of every
// acceptance-test config. It is built once from CIPHERTRUST_* environment
// variables so that no sed-based source-file patching is needed in CI.
// Hardcoded fallbacks preserve backward compatibility for local dev machines
// that do not export these variables.
//
// CDSPaaS mode (CIPHERTRUST_TENANT set): includes `tenant`; omits
// domain/auth_domain (they are irrelevant and provoke a provider warning).
//
// CM mode (CIPHERTRUST_TENANT empty): includes domain + auth_domain.
var providerConfig = func() string {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	if address == "" {
		address = "https://192.168.2.135"
	}
	username := os.Getenv("CIPHERTRUST_USERNAME")
	if username == "" {
		username = "admin"
	}
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	if password == "" {
		password = "ChangeIt01!"
	}
	tenant := os.Getenv("CIPHERTRUST_TENANT")

	cfg := fmt.Sprintf(`
provider "ciphertrust" {
  address   = %q
  username  = %q
  password  = %q
  bootstrap = "no"
`, address, username, password)

	// Acceptance tests run against lab/CI CipherTrust Managers that present
	// self-signed certificates (often without proper IP SANs). Honour
	// CIPHERTRUST_CA_CERT if the operator has supplied a trusted bundle for
	// the test target; otherwise opt into skip-verify so tests aren't blocked
	// by the production-grade default introduced for end users.
	if caCert := os.Getenv("CIPHERTRUST_CA_CERT"); caCert != "" {
		cfg += fmt.Sprintf("  ca_cert = %q\n", caCert)
	} else {
		cfg += "  no_ssl_verify = true\n"
	}

	if tenant != "" {
		// CDSPaaS: tenant drives auth_domain_path; domain/auth_domain unused.
		cfg += fmt.Sprintf("  tenant = %q\n", tenant)
	} else {
		// On-prem CM: explicit domain and auth_domain.
		domain := os.Getenv("CIPHERTRUST_DOMAIN")
		if domain == "" {
			domain = "root"
		}
		authDomain := os.Getenv("CIPHERTRUST_AUTH_DOMAIN")
		if authDomain == "" {
			authDomain = "root"
		}
		cfg += fmt.Sprintf("  domain      = %q\n", domain)
		cfg += fmt.Sprintf("  auth_domain = %q\n", authDomain)
	}
	cfg += "}\n"
	return cfg
}()

var (
	testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
		"ciphertrust": providerserver.NewProtocol6WithError(New("ciphertrust")()),
	}
)

// cipherTrustVersion caches the result of getCipherTrustVersion so that the API
// is called at most once per test run. A value of 0 means not yet fetched.
var cipherTrustVersion int

// devCMVersionValue is a sentinel returned by getCipherTrustVersion when the
// server reports version "Development", or when the CIPHERTRUST_* environment
// variables needed to reach the test target are not set.
const devCMVersionValue = 9999

// getCipherTrustVersion returns an integer encoding of the CipherTrust Manager
// version at the test target, used by tests that conditionally check behaviour
// introduced in a specific release. The encoding concatenates the major and minor
// version digits: e.g. 2.24.0-beta7+51895 -> 224, 2.21.2 -> 221.
//
// The result is cached after the first successful call so that multiple tests in
// the same run do not repeat the API round-trip.
//
// Returns devCMVersionValue if the version cannot be determined due to a connection
// or parse error.
func getCipherTrustVersion() int {
	if cipherTrustVersion != 0 {
		fmt.Printf("Test System Version: %d\n", cipherTrustVersion)
		return cipherTrustVersion
	}
	cipherTrustVersion = devCMVersionValue
	if os.Getenv("CDSPAAS") == "true" {
		fmt.Printf("CDSPAAS is true, returning %d\n", cipherTrustVersion)
		return cipherTrustVersion
	}
	var (
		err      error
		client   *common.Client
		response string
	)
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	domain := "root"
	if address == "" || username == "" || password == "" {
		fmt.Printf("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD environment variables must be set to get the system version, returning %d\n", devCMVersionValue)
		return devCMVersionValue
	}
	client, err = common.NewClient(context.Background(), uuid.NewString(), &address, &domain, &domain, &username, &password, nil, common.TLSOptions{InsecureSkipVerify: true}, 180)
	if err != nil {
		fmt.Printf("** Failed to create client, returning %d. err: %s\n", cipherTrustVersion, err.Error())
		return cipherTrustVersion
	}
	response, err = client.GetById(context.Background(), "", "", common.URL_SYSTEMINFO)
	if err != nil {
		fmt.Printf("** Failed get system info, returning %d. err: %s\n", cipherTrustVersion, err.Error())
		return cipherTrustVersion
	}

	version := gjson.Get(response, "version").String()
	fmt.Printf("SysInfo Version: %v\n", version)
	if version == "" {
		fmt.Printf("** System version is empty, returning %d\n", cipherTrustVersion)
		return cipherTrustVersion
	}
	if version == "Development" {
		fmt.Printf("** System version is Development, returning %d\n", devCMVersionValue)
		return devCMVersionValue
	}
	versions := strings.Split(version, ".")
	if len(versions) < 2 {
		fmt.Printf("** Unable to determine system version from '%s', returning %d\n", version, cipherTrustVersion)
		return cipherTrustVersion
	}
	cipherTrustVersion, err = strconv.Atoi(versions[0] + versions[1])
	if err != nil {
		fmt.Printf("** Failed to convert %s to int, returning %d. Error: %s\n", versions[0]+versions[1], devCMVersionValue, err.Error())
		return devCMVersionValue
	}
	fmt.Printf("Test System Version: %d\n", cipherTrustVersion)
	return cipherTrustVersion
}

// testCheckAttributeContains verifies that a single string attribute on a resource
// either contains or does not contain all of the provided substrings, depending on
// the value of the contains flag.
// For example, to assert that an IAM policy JSON string includes two ARNs:
//
//	testCheckAttributeContains(keyResource, "policy", []string{"arn:aws:...:user/alice", "arn:aws:...:role/admin"}, true)
func testCheckAttributeContains(resourceName string, attributeName string, stringsToFind []string, contains bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for rn, rs := range s.RootModule().Resources {
			if rn != resourceName {
				continue
			}
			if rs.Primary.ID == "" {
				return fmt.Errorf("error: %s resource ID is not set", resourceName)
			}
			keys := make([]string, 0, len(rs.Primary.Attributes))
			for k := range rs.Primary.Attributes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			found := false
			for _, k := range keys {
				if k == attributeName {
					found = true
					for _, str := range stringsToFind {
						if contains {
							if !strings.Contains(rs.Primary.Attributes[k], str) {
								return fmt.Errorf("error: %s.%s does not contain %s", resourceName, attributeName, str)
							}
						} else {
							if strings.Contains(rs.Primary.Attributes[k], str) {
								return fmt.Errorf("error: %s.%s does contain %s", resourceName, attributeName, str)
							}
						}
					}
				}
			}
			if !found {
				return fmt.Errorf("error: did not find %s.%s", resourceName, attributeName)
			}
			return nil
		}
		return fmt.Errorf("error: did not find resource %s so can't list attributes", resourceName)
	}
}

// testCheckListContainsName verifies that at least one element in a list
// attribute of a datasource has a specific value for the given sub-attribute.
// For example, to verify that the "scheduler" list contains a scheduler whose
// "name" equals "my-scheduler":
//
//	testCheckListContainsName("data.ciphertrust_scheduler_list.ds", "scheduler", "name", "my-scheduler")
func testCheckListContainsName(resourceName string, listAttr string, subAttr string, expectedValue string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("error: did not find resource %s", resourceName)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("error: %s resource ID is not set", resourceName)
		}
		countStr, ok := rs.Primary.Attributes[listAttr+".#"]
		if !ok {
			return fmt.Errorf("error: %s.%s.# not found in state", resourceName, listAttr)
		}
		count := 0
		fmt.Sscanf(countStr, "%d", &count)
		for i := 0; i < count; i++ {
			key := fmt.Sprintf("%s.%d.%s", listAttr, i, subAttr)
			if rs.Primary.Attributes[key] == expectedValue {
				return nil
			}
		}
		return fmt.Errorf("error: %s list in %s does not contain an entry with %s = %q", listAttr, resourceName, subAttr, expectedValue)
	}
}

// testVerifyResourceDeleted asserts that resourceName is no longer present in the
// Terraform state, confirming it was destroyed. There is no built-in equivalent
// in the terraform-plugin-testing library - TestCheckNoResourceAttr only checks
// that a specific attribute is absent, not that the resource itself is gone.
func testVerifyResourceDeleted(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		if _, ok := s.RootModule().Resources[resourceName]; ok {
			return fmt.Errorf("error: resource %s still exists", resourceName)
		}
		return nil
	}
}

// testAccListResourceAttributes is a debugging helper that prints every attribute
// for a resource to stdout. It is not called by any test but is kept here because
// it is very useful when writing or diagnosing new tests.
// NOTE: calls to this function must not be left in committed source code.
func testAccListResourceAttributes(step string, resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		fmt.Printf("\n************ %s %s attributes\n", step, resourceName)
		for rn, rs := range s.RootModule().Resources {
			if rn != resourceName {
				continue
			}
			if rs.Primary.ID == "" {
				return fmt.Errorf("error: %s resource ID is not set", resourceName)
			}
			keys := make([]string, 0, len(rs.Primary.Attributes))
			for k := range rs.Primary.Attributes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("k:%s v:%v\n", k, rs.Primary.Attributes[k])
			}
			fmt.Printf("**************** end %s %s attributes\n\n", step, resourceName)
			return nil
		}
		return fmt.Errorf("error: did not find resource %s so can't list attributes", resourceName)
	}
}

// testAccListResources is a debugging helper that prints the name and type of every
// resource in the current Terraform state. It is not called by any test but is kept
// here because it is very useful when writing or diagnosing new tests.
// NOTE: calls to this function must not be left in committed source code.
func testAccListResources() resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for rn, rs := range s.RootModule().Resources {
			fmt.Printf("rn: %s rt: %s\n", rn, rs.Type)
		}
		return nil
	}
}

// createCMClient constructs a common.Client from the standard CIPHERTRUST_*
// environment variables. Returns the client and true on success, or nil and
// false when any required variable is missing or the client cannot be created.
// The caller is responsible for logging any skip/error message.
//
// When CDSPAAS=true the auth_domain is read from CIPHERTRUST_AUTH_DOMAIN,
// domain is left empty, and tenant is read from CIPHERTRUST_TENANT (used as
// auth_domain_path on the auth-token request). Otherwise both domain and
// auth_domain are read from CIPHERTRUST_DOMAIN and CIPHERTRUST_AUTH_DOMAIN
// respectively, and tenant is not used.
func createCMClient() (*common.Client, bool) {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	if address == "" || username == "" || password == "" {
		fmt.Println("createCMClient: CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
		return nil, false
	}
	var domain string
	authDomain := os.Getenv("CIPHERTRUST_AUTH_DOMAIN")
	var tenant *string
	if os.Getenv("CDSPAAS") == "true" {
		t := os.Getenv("CIPHERTRUST_TENANT")
		tenant = &t
	} else {
		domain = os.Getenv("CIPHERTRUST_DOMAIN")
	}
	client, err := common.NewClient(context.Background(), uuid.NewString(), &address, &authDomain, &domain, &username, &password, tenant, common.TLSOptions{InsecureSkipVerify: true}, 180)
	if err != nil {
		tenantVal := ""
		if tenant != nil {
			tenantVal = *tenant
		}
		fmt.Printf("createCMClient: failed to create client: \n"+
			"Error: %s\n"+
			"CIPHERTRUST_ADDRESS:     %s\n"+
			"CIPHERTRUST_USERNAME:    %s\n"+
			"CIPHERTRUST_AUTH_DOMAIN: %s\n"+
			"CIPHERTRUST_DOMAIN:      %s\n"+
			"CIPHERTRUST_TENANT:      %s\n"+
			"CDSPAAS:                 %s\n",
			err.Error(), address, username, authDomain, domain,
			tenantVal, os.Getenv("CDSPAAS"))
		return nil, false
	}
	return client, true
}
