package cte

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// pagedListWarningThreshold is the result-set size above which CTE list data
// sources emit a warning diagnostic when the caller has not set an explicit
// "limit". CTE list endpoints page internally at 256 records per request
// (see cteListPageSize in common/requests.go); a threshold of 1000 (~4
// pages) is high enough to stay quiet for routine deployments while still
// flagging genuinely large CM inventories (e.g. tens of thousands of CTE
// clients) that would otherwise be fetched in full on every terraform
// refresh with no way to bound the request (TFIN-584).
const pagedListWarningThreshold = 1000

// resolvePagedListParams derives the skip/limit values to pass to
// GetAllPagedWithLimit from a data source's optional "skip"/"limit" schema
// attributes. limit == 0 means "unset": fetch everything, preserving
// backward-compatible behavior for existing configurations that don't set
// either attribute.
func resolvePagedListParams(limit, skip types.Int64) (limitVal, skipVal int64) {
	if !skip.IsNull() && !skip.IsUnknown() {
		skipVal = skip.ValueInt64()
	}
	if !limit.IsNull() && !limit.IsUnknown() {
		limitVal = limit.ValueInt64()
	}
	return limitVal, skipVal
}

// warnIfPagedResultLarge emits a warning diagnostic when total exceeds
// pagedListWarningThreshold and the caller did not specify an explicit
// limit, so users on large CM deployments know they can bound the result
// set via the "limit"/"skip" attributes instead of always retrieving the
// entire list on every refresh (TFIN-584).
func warnIfPagedResultLarge(diags *diag.Diagnostics, resourceLabel string, total, limitVal int64) {
	if limitVal > 0 {
		return
	}
	if total <= pagedListWarningThreshold {
		return
	}
	diags.AddWarning(
		"Large Result Set",
		fmt.Sprintf("This data source retrieved all %d %s from CipherTrust Manager because no 'limit' was specified. On large deployments this can be slow and will be repeated on every terraform refresh. Set the 'limit' (and optionally 'skip') attribute to bound the result set.", total, resourceLabel),
	)
}

// handleDeleteNotFound centralizes CTE resource Delete() 404 handling.
// Call it when a Delete API call (DeleteByID/DeleteByURL/UpdateData unguard,
// etc.) returns a non-nil err. If the error is a 404 -- meaning the
// resource is already gone on CipherTrust Manager, e.g. deleted
// out-of-band via console, direct API, or a DR operation -- it adds a
// warning diagnostic and returns true: the caller should treat this as
// idempotent success (return, or continue a per-item loop, without adding
// an error) so Terraform removes the resource from state. If the error is
// not a 404 (a genuine error), it returns false and adds nothing, leaving
// the caller's existing resp.Diagnostics.AddError(...) handling unchanged.
func handleDeleteNotFound(err error, resourceLabel string, diags *diag.Diagnostics) bool {
	if !strings.Contains(err.Error(), "status: 404") {
		return false
	}
	diags.AddWarning(
		fmt.Sprintf("%s already deleted", resourceLabel),
		fmt.Sprintf("%s was not found on CipherTrust Manager during delete, indicating it was already removed out-of-band (e.g. console, direct API, or a DR operation). Treating delete as successful.", resourceLabel),
	)
	return true
}

// handleReadNotFound centralizes CTE resource Read() 404/error handling.
// On err == nil it does nothing and returns false (caller proceeds normally).
// On ANY error -- including a 404 -- it adds a hard diagnostic error and
// leaves state untouched (does NOT remove the resource), per TFIN-623's
// universal CTE Read()/Update() 404 policy: a 404 during refresh must fail
// loudly rather than being silently tolerated, since the user has no other
// signal that Terraform's view of the resource has diverged from reality.
// (Previously a 404 here only added a warning -- commit 43f3b14/TFIN-185 --
// which kept state correctly but under-reported the severity; TFIN-623
// keeps the state-preserving behavior and raises the severity to AddError.)
// Returns true if the caller should return immediately.
func handleReadNotFound(ctx context.Context, err error, resourceLabel string, diags *diag.Diagnostics) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "status: 404") {
		diags.AddError(
			fmt.Sprintf("%s not found", resourceLabel),
			fmt.Sprintf("%s was not found on CipherTrust Manager during refresh. Keeping it in Terraform state rather than removing it, since this may be a transient issue or a change that should be reconciled deliberately.", resourceLabel),
		)
		return true
	}
	diags.AddError(
		fmt.Sprintf("Error reading %s", resourceLabel),
		err.Error(),
	)
	return true
}

// handleRuleReadNotFound extends handleReadNotFound for CTE policy sub-rule
// Read() implementations (datatxrules/keyrules/ldtkeyrules/securityrules),
// which historically detected "not found" via `response == ""` alone. Since
// Client.GetById/doRequest return ("", err) uniformly for EVERY non-2xx
// status -- not just 404 -- checking response=="" without first checking
// err misclassifies ANY failure (a transient 500, an expired-token 401, a
// network error) as "rule deleted out-of-band" and silently wipes it from
// state (TFIN-623). This defers to handleReadNotFound for the err-based
// checks first (both a genuine 404 and any other error now AddError + keep
// state), then applies the same AddError + keep-state treatment for the
// residual response=="" case with err == nil. Returns true if the caller
// should return immediately.
func handleRuleReadNotFound(ctx context.Context, err error, response string, resourceLabel string, diags *diag.Diagnostics) bool {
	if handleReadNotFound(ctx, err, resourceLabel, diags) {
		return true
	}
	if response == "" {
		diags.AddError(
			fmt.Sprintf("%s not found", resourceLabel),
			fmt.Sprintf("%s returned an empty response from CipherTrust Manager during refresh, indicating it may have been removed out-of-band. Keeping it in Terraform state rather than removing it, since this may be a transient issue or a change that should be reconciled deliberately.", resourceLabel),
		)
		return true
	}
	return false
}

// normalizeCTEResourceSetName resolves a CTE resource set reference (which a
// user may supply as either the resource set's UUID or its name) to the
// resource set's canonical name, the form CipherTrust Manager itself always
// stores/echoes back on a policy rule's resource_set_id (confirmed via GET
// on datatxrules/keyrules/securityrules). CM's GET
// /transparent-encryption/resourcesets/{id} endpoint accepts either a UUID
// or a name in the same path parameter, so a single lookup handles both
// input forms.
//
// This exists to let ModifyPlan compare a rule's planned (config-sourced)
// resource_set_id against its refreshed (CM-sourced, name-form) state value
// in the same representation (TFIN-610): without it, a config supplying a
// UUID would show a perpetual diff against the name Read() now always
// refreshes state with -- the same visible bug TFIN-470 originally
// described, reintroduced by fixing the silent-drift variant.
//
// If idOrName is empty, or the lookup fails for any reason (transient error,
// or a value that is not a resolvable resource set at all), idOrName is
// returned unchanged so callers fail closed to "no normalization" rather
// than risking corrupting an otherwise-valid value.
func normalizeCTEResourceSetName(ctx context.Context, client *common.Client, idOrName string) string {
	if idOrName == "" {
		return idOrName
	}
	response, err := client.GetById(ctx, uuid.New().String(), idOrName, common.URL_CTE_RESOURCE_SET)
	if err != nil || response == "" {
		return idOrName
	}
	var rs CTEResourceSetJSON
	if err := json.Unmarshal([]byte(response), &rs); err != nil || rs.Name == "" {
		return idOrName
	}
	return rs.Name
}

// modifyPlanCTERuleResourceSetID centralizes the ModifyPlan logic shared by
// resource_cte_policy_datatxrules.go, resource_cte_policy_keyrules.go, and
// resource_cte_policy_securityrules.go for normalizing rule.resource_set_id
// (TFIN-610). planRSID is the resource_set_id value from the raw generated
// plan (config-sourced, may be a UUID or a name); stateRSID is the
// resource_set_id value from the refreshed prior state (always name-form,
// per Read()). If they already match, or the plan value is unknown (create),
// there is nothing to normalize. Otherwise, resolve planRSID to its
// canonical name and compare against stateRSID: if they refer to the same
// resource set, return (stateRSID, true) so the caller can pin the plan to
// the existing state value and suppress a meaningless representation-only
// diff; if they genuinely differ, return ("", false) and the caller leaves
// the diff untouched so real drift/changes still surface normally.
func modifyPlanCTERuleResourceSetID(ctx context.Context, client *common.Client, planRSID, stateRSID string, planKnown bool) (string, bool) {
	if !planKnown || planRSID == stateRSID {
		return "", false
	}
	if normalizeCTEResourceSetName(ctx, client, planRSID) == stateRSID {
		return stateRSID, true
	}
	return "", false
}
