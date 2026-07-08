package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

var testGroupName = "TFTestGroup-" + uuid.New().String()[:8]

func cmGroupConfig(name, description, appMeta string) string {
	cfg := fmt.Sprintf(`
resource "ciphertrust_groups" "testGroup" {
  name = %q
`, name)
	if description != "" {
		cfg += fmt.Sprintf("  description = %q\n", description)
	}
	if appMeta != "" {
		cfg += fmt.Sprintf("  app_metadata = %q\n", appMeta)
	}
	cfg += "}\n"
	return providerConfig + cfg
}

// TestAccCMGroup_nameImmutable verifies that changing the group name is blocked at plan
// time with a clear error, leaving the original group untouched on CM.
func TestAccCMGroup_nameImmutable(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig(testGroupName+"Immutable", "Original", ""),
				Check: checkStep(t, "name immutable: create",
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "name", testGroupName+"Immutable"),
				),
			},
			// Renaming must be blocked at plan time with a clear error.
			{
				Config:      cmGroupConfig(testGroupName+"ImmutableRenamed", "Original", ""),
				ExpectError: regexp.MustCompile(`(?i)immutable`),
				PlanOnly:    true,
			},
		},
	})
}

func TestAccCMGroup_basicCreate(t *testing.T) {
	name := "TFTestGroup-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig(name, "Created via TF", `{"env":"test"}`),
				Check: checkStep(t, "basic create",
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "id"),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "Created via TF"),
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "app_metadata"),
				),
			},
			// Verify no drift on a subsequent plan.
			{
				Config:             cmGroupConfig(name, "Created via TF", `{"env":"test"}`),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCMGroup_driftDetection(t *testing.T) {
	name := "TFTestGroupDrift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig(name, "Drift test", ""),
				Check: checkStep(t, "drift detection: create",
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_groups.testGroup"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion; next plan should detect drift and recreate.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_GROUP+"/"+capturedID,
					)
				},
				Config:             cmGroupConfig(name, "Drift test", ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// cmGroupWithUsersConfig renders a group resource with the given user_ids
// expression appended literally. usernames is a list of usernames that should
// be declared as ciphertrust_user resources; their IDs can be referenced from
// userIDsExpr via ciphertrust_user.<sanitized_username>.id.
//
// Pass userIDsExpr = "" to omit the user_ids attribute entirely (verifies the
// "leave membership unmanaged" path).
func cmGroupWithUsersConfig(groupName string, usernames []string, userIDsExpr string) string {
	var b strings.Builder
	b.WriteString(providerConfig)
	for _, u := range usernames {
		b.WriteString(fmt.Sprintf(`
resource "ciphertrust_user" "%s" {
  username = %q
  password = "CHAnge012!@#"
}
`, sanitizeTFName(u), u))
	}
	b.WriteString(fmt.Sprintf(`
resource "ciphertrust_groups" "testGroup" {
  name = %q
`, groupName))
	if userIDsExpr != "" {
		b.WriteString(fmt.Sprintf("  user_ids = %s\n", userIDsExpr))
	}
	b.WriteString("}\n")
	return b.String()
}

// sanitizeTFName turns a username into a valid Terraform identifier
// (lowercase, dashes → underscores).
func sanitizeTFName(s string) string {
	return strings.ReplaceAll(s, "-", "_")
}

// checkGroupMembership asserts the live group on CM contains exactly the user
// IDs found in state on the named ciphertrust_user resources.
func checkGroupMembership(groupResourceName string, userResourceNames ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		group, ok := s.RootModule().Resources[groupResourceName]
		if !ok {
			return fmt.Errorf("group resource %s not in state", groupResourceName)
		}
		groupName := group.Primary.Attributes["name"]

		expected := make([]string, 0, len(userResourceNames))
		for _, name := range userResourceNames {
			u, ok := s.RootModule().Resources[name]
			if !ok {
				return fmt.Errorf("user resource %s not in state", name)
			}
			expected = append(expected, u.Primary.ID)
		}
		sort.Strings(expected)

		client, ok := createCMClient()
		if !ok {
			return fmt.Errorf("could not build CM client; required CIPHERTRUST_* env vars not set")
		}
		members, err := listGroupMembersForTest(client, groupName)
		if err != nil {
			return fmt.Errorf("failed to list members of group %q: %w", groupName, err)
		}
		sort.Strings(members)

		if len(members) != len(expected) {
			return fmt.Errorf("group %q membership mismatch: got %v, expected %v", groupName, members, expected)
		}
		for i := range members {
			if members[i] != expected[i] {
				return fmt.Errorf("group %q membership mismatch: got %v, expected %v", groupName, members, expected)
			}
		}
		return nil
	}
}

// listGroupMembersForTest fetches the user_id of every user in groupName
// directly from CM. Mirrors what the provider's Read does so tests can verify
// the live state independent of provider behavior.
func listGroupMembersForTest(client *common.Client, groupName string) ([]string, error) {
	body, err := client.GetAll(
		context.Background(),
		uuid.NewString(),
		common.URL_USER_MANAGEMENT+"/?groups="+groupName+"&skip=0&limit=-1",
	)
	if err != nil {
		return nil, err
	}
	out := []string{}
	// GetAll already returns the "resources" array as a JSON string.
	for _, line := range splitJSONArray(body) {
		if id := extractUserID(line); id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

// splitJSONArray splits a flat JSON array string of objects into per-object
// substrings. We avoid pulling gjson into the test by walking the brackets.
func splitJSONArray(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	out := []string{}
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			depth--
			if depth == 0 {
				out = append(out, s[start:i+1])
			}
		}
	}
	return out
}

// extractUserID does a very small "find user_id field in this JSON object" —
// we don't want to depend on gjson from tests so this is a hand-rolled match.
func extractUserID(obj string) string {
	const key = `"user_id"`
	idx := strings.Index(obj, key)
	if idx < 0 {
		return ""
	}
	rest := obj[idx+len(key):]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// TestAccCMGroup_userIDsCreate verifies that user_ids on Create adds the
// referenced users to the group, that the field round-trips through state,
// and that a subsequent plan reports no drift.
func TestAccCMGroup_userIDsCreate(t *testing.T) {
	suffix := uuid.New().String()[:8]
	groupName := "TFTestGroupUsers-" + suffix
	username := "tf-test-user-" + suffix
	userIDsExpr := fmt.Sprintf("[ciphertrust_user.%s.id]", sanitizeTFName(username))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupWithUsersConfig(groupName, []string{username}, userIDsExpr),
				Check: checkStep(t, "user_ids: create with one user",
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "user_ids.#", "1"),
					checkGroupMembership(
						"ciphertrust_groups.testGroup",
						"ciphertrust_user."+sanitizeTFName(username),
					),
				),
			},
			{
				Config:             cmGroupWithUsersConfig(groupName, []string{username}, userIDsExpr),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCMGroup_userIDsAddRemove walks the membership through three states:
// one user → two users → one user. Each transition must reconcile via the
// add-user / remove-user endpoints and end with the live group matching state.
func TestAccCMGroup_userIDsAddRemove(t *testing.T) {
	suffix := uuid.New().String()[:8]
	groupName := "TFTestGroupAddRem-" + suffix
	userA := "tf-test-usera-" + suffix
	userB := "tf-test-userb-" + suffix
	exprA := fmt.Sprintf("[ciphertrust_user.%s.id]", sanitizeTFName(userA))
	exprAB := fmt.Sprintf("[ciphertrust_user.%s.id, ciphertrust_user.%s.id]", sanitizeTFName(userA), sanitizeTFName(userB))
	exprB := fmt.Sprintf("[ciphertrust_user.%s.id]", sanitizeTFName(userB))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupWithUsersConfig(groupName, []string{userA, userB}, exprA),
				Check: checkStep(t, "user_ids: initial membership = A",
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "user_ids.#", "1"),
					checkGroupMembership(
						"ciphertrust_groups.testGroup",
						"ciphertrust_user."+sanitizeTFName(userA),
					),
				),
			},
			{
				Config: cmGroupWithUsersConfig(groupName, []string{userA, userB}, exprAB),
				Check: checkStep(t, "user_ids: add B → membership = {A, B}",
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "user_ids.#", "2"),
					checkGroupMembership(
						"ciphertrust_groups.testGroup",
						"ciphertrust_user."+sanitizeTFName(userA),
						"ciphertrust_user."+sanitizeTFName(userB),
					),
				),
			},
			{
				Config: cmGroupWithUsersConfig(groupName, []string{userA, userB}, exprB),
				Check: checkStep(t, "user_ids: remove A → membership = B",
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "user_ids.#", "1"),
					checkGroupMembership(
						"ciphertrust_groups.testGroup",
						"ciphertrust_user."+sanitizeTFName(userB),
					),
				),
			},
		},
	})
}

// TestAccCMGroup_userIDsDrift verifies that out-of-band removal of a user
// from the group is detected on the next plan (Read populates user_ids from
// the live API, not from cached state).
func TestAccCMGroup_userIDsDrift(t *testing.T) {
	suffix := uuid.New().String()[:8]
	groupName := "TFTestGroupUserDrift-" + suffix
	username := "tf-test-driftuser-" + suffix
	userIDsExpr := fmt.Sprintf("[ciphertrust_user.%s.id]", sanitizeTFName(username))
	var capturedUserID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupWithUsersConfig(groupName, []string{username}, userIDsExpr),
				Check: checkStep(t, "user_ids drift: create",
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "user_ids.#", "1"),
					func(s *terraform.State) error {
						u, ok := s.RootModule().Resources["ciphertrust_user."+sanitizeTFName(username)]
						if !ok {
							return fmt.Errorf("user resource not found in state")
						}
						capturedUserID = u.Primary.ID
						return nil
					},
				),
			},
			{
				// Drop the user out-of-band; provider must detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_GROUP+"/"+groupName+"/users/"+capturedUserID,
					)
				},
				Config:             cmGroupWithUsersConfig(groupName, []string{username}, userIDsExpr),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_userIDsOmittedUnmanaged verifies that omitting user_ids from
// config leaves membership unmanaged: pre-existing members added out-of-band
// remain in the group, and the plan stays empty.
func TestAccCMGroup_userIDsOmittedUnmanaged(t *testing.T) {
	suffix := uuid.New().String()[:8]
	groupName := "TFTestGroupUnmanaged-" + suffix
	username := "tf-test-unmanaged-" + suffix

	var capturedUserID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create the group + user with no user_ids managed.
				Config: cmGroupWithUsersConfig(groupName, []string{username}, ""),
				Check: checkStep(t, "user_ids omitted: create with empty membership",
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "user_ids.#", "0"),
					func(s *terraform.State) error {
						u, ok := s.RootModule().Resources["ciphertrust_user."+sanitizeTFName(username)]
						if !ok {
							return fmt.Errorf("user resource not found in state")
						}
						capturedUserID = u.Primary.ID
						return nil
					},
				),
			},
			{
				// Add the user out-of-band. Because user_ids is unmanaged
				// (omitted from config), Read picks up the new membership and
				// the plan modifier copies it forward — the plan must be empty.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.PostNoData(
						context.Background(),
						uuid.NewString(),
						common.URL_GROUP+"/"+groupName+"/users/"+capturedUserID,
					)
				},
				Config:             cmGroupWithUsersConfig(groupName, []string{username}, ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCMGroup_attributeDrift(t *testing.T) {
	name := "TFTestGroupAttrDrift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig(name, "Original description", ""),
				Check: checkStep(t, "attribute drift: create",
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "Original description"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_groups.testGroup"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band description change; next plan should detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload := []byte(`{"description":"Out-of-band modified"}`)
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_GROUP,
						patchPayload,
						"name",
					)
				},
				Config:             cmGroupConfig(name, "Original description", ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
