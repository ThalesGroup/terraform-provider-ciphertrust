package cte

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

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
