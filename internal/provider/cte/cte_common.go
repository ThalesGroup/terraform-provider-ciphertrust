package cte

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

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
