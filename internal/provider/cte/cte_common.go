package cte

import (
	"context"
	"fmt"
	"strings"

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
// On a genuine error it adds a diagnostic error. On a 404 specifically it
// adds a warning and leaves state untouched (does NOT remove the resource),
// per this project's conservative-on-404 convention (commit 43f3b14, TFIN-185).
// Returns true if the caller should return immediately.
func handleReadNotFound(ctx context.Context, err error, resourceLabel string, diags *diag.Diagnostics) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "status: 404") {
		diags.AddWarning(
			fmt.Sprintf("%s not found", resourceLabel),
			fmt.Sprintf("%s was not found on CipherTrust Manager during refresh. Keeping it in Terraform state rather than removing it, in case this is a transient issue.", resourceLabel),
		)
		return true
	}
	diags.AddError(
		fmt.Sprintf("Error reading %s", resourceLabel),
		err.Error(),
	)
	return true
}
