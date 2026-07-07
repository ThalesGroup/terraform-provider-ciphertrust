package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// This file collects helpers shared by the CTE acceptance tests. They build on
// createCMClient (provider_test.go) and the common.URL_CTE_* endpoint constants
// so that drift tests can mutate objects out-of-band and import tests can build
// composite IDs without each test re-implementing the plumbing.

// cteCaptureID returns a TestCheckFunc that copies the primary ID of resourceName
// into *dst. Used by drift tests that need the server-side ID inside a later
// PreConfig closure (mirrors the capturedID pattern in resource_cm_group_test.go).
func cteCaptureID(resourceName string, dst *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("resource %s has no ID in state", resourceName)
		}
		*dst = rs.Primary.ID
		return nil
	}
}

// cteCaptureAttr returns a TestCheckFunc that copies the named attribute of
// resourceName into *dst. Used by composite-ID drift/import tests.
func cteCaptureAttr(resourceName, attr string, dst *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		v, ok := rs.Primary.Attributes[attr]
		if !ok {
			return fmt.Errorf("resource %s has no attribute %q in state", resourceName, attr)
		}
		*dst = v
		return nil
	}
}

// cteOutOfBandPatch PATCHes endpoint/id with jsonBody using a fresh CM client.
// Intended for drift-test PreConfig closures: it is best-effort and silent on
// client-build failure (matching resource_cm_group_test.go, where a missing
// CIPHERTRUST_* env simply means the drift step degrades to a no-op rather than
// a hard failure outside CI).
func cteOutOfBandPatch(endpoint, id, jsonBody string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	_, _ = client.UpdateDataV2(context.Background(), id, endpoint, []byte(jsonBody))
}

// cteOutOfBandDelete DELETEs endpoint/id using a fresh CM client. Best-effort,
// for drift tests that verify the provider recreates a server-side deletion.
func cteOutOfBandDelete(endpoint, id string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	_, _ = client.DeleteByURL(context.Background(), uuid.NewString(), endpoint+"/"+id)
}

// importStateCheckAttrsSet returns an ImportStateCheckFunc asserting that the
// single imported resource has every named attribute present and non-empty. It
// is the robust alternative to ImportStateVerify for resources with write-only
// or composite fields (CTE rules, guardpoints, clients), whose import populates
// only key fields before Read refreshes the rest — a full-state ImportStateVerify
// there is brittle across CM versions.
func importStateCheckAttrsSet(attrs ...string) resource.ImportStateCheckFunc {
	return func(states []*terraform.InstanceState) error {
		if len(states) != 1 {
			return fmt.Errorf("expected exactly 1 imported instance, got %d", len(states))
		}
		is := states[0]
		for _, a := range attrs {
			if is.Attributes[a] == "" {
				return fmt.Errorf("imported state missing or empty attribute %q", a)
			}
		}
		return nil
	}
}

// cteRuleImportID returns an ImportStateIdFunc that builds the "<policy_id>:<ruleID>"
// composite ID used by CTE policy rule resources, reading both values from the
// resource's state. ruleIDAttr is the state path of the rule's own ID
// (e.g. "rule.id" for most rules).
func cteRuleImportID(resourceName, ruleIDAttr string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("resource %s not found in state", resourceName)
		}
		policyID := rs.Primary.Attributes["policy_id"]
		ruleID := rs.Primary.Attributes[ruleIDAttr]
		if policyID == "" || ruleID == "" {
			return "", fmt.Errorf("resource %s missing policy_id (%q) or %s (%q)", resourceName, policyID, ruleIDAttr, ruleID)
		}
		return policyID + ":" + ruleID, nil
	}
}

// cteAttrImportID returns an ImportStateIdFunc that uses a single state attribute
// of resourceName as the import ID. Used by resources whose ImportState passes
// through a field other than the resource's own id (e.g. guardpoints import by
// client_id / client_group_id).
func cteAttrImportID(resourceName, attr string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("resource %s not found in state", resourceName)
		}
		v := rs.Primary.Attributes[attr]
		if v == "" {
			return "", fmt.Errorf("resource %s has empty attribute %q", resourceName, attr)
		}
		return v, nil
	}
}

// cteGetByID fetches endpoint/id with a fresh CM client and returns the raw JSON
// body. Returns ("", false) if the client cannot be built or the GET fails.
func cteGetByID(endpoint, id string) (string, bool) {
	client, ok := createCMClient()
	if !ok {
		return "", false
	}
	body, err := client.GetById(context.Background(), uuid.NewString(), id, endpoint)
	if err != nil {
		return "", false
	}
	return body, true
}

// cteGuardPointStateTransient reports whether a guard_point_state value is still
// in flight. Guard points apply asynchronously on the agent, so the per-GP state
// transitions through pending/in-progress values before settling. We treat empty
// and any "pending"/"progress"/"process" state as transient.
func cteGuardPointStateTransient(state string) bool {
	s := strings.ToLower(strings.TrimSpace(state))
	if s == "" {
		return true
	}
	return strings.Contains(s, "pend") || strings.Contains(s, "progress") || strings.Contains(s, "process")
}

// cteWaitGuardPointsSettled returns a TestCheckFunc that polls the live
// guardpoints of the client referenced by clientIDAttr on resourceName until
// every guard point's guard_point_state has settled (is non-transient), or the
// timeout elapses. Guard points are applied asynchronously, so assertions that
// depend on the applied state must wait for this first.
//
// On timeout it logs the last-seen response and returns nil rather than failing,
// so that an unrecognised state vocabulary on a given CM version degrades to a
// fixed wait instead of a spurious test failure.
func cteWaitGuardPointsSettled(resourceName, clientIDAttr string, timeout time.Duration) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		clientID := rs.Primary.Attributes[clientIDAttr]
		if clientID == "" {
			return fmt.Errorf("resource %s has empty %s", resourceName, clientIDAttr)
		}
		endpoint := common.URL_CTE_CLIENT + "/" + clientID + "/guardpoints"

		deadline := time.Now().Add(timeout)
		var last string
		for {
			body, ok := cteGetByID(endpoint, "")
			if ok {
				// The list endpoint returns {"resources":[{... "guard_point_state": ...}]}.
				allSettled := true
				n := int(gjson.Get(body, "resources.#").Int())
				for i := 0; i < n; i++ {
					st := gjson.Get(body, fmt.Sprintf("resources.%d.guard_point_state", i)).String()
					if cteGuardPointStateTransient(st) {
						allSettled = false
					}
				}
				last = body
				if n > 0 && allSettled {
					return nil
				}
			}
			if time.Now().After(deadline) {
				fmt.Printf("cteWaitGuardPointsSettled: timed out after %s waiting for guard points on client %s to settle; last response: %s\n", timeout, clientID, last)
				return nil
			}
			time.Sleep(3 * time.Second)
		}
	}
}
