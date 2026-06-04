package cm

import (
	"context"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// cmNotFoundError is the substring present in the error returned by the CM
// client (see common/client.go -> doRequest, which formats non-2xx responses as
// "status: %d, body: %s") when CipherTrust Manager responds with HTTP 404. The
// equivalent constant in the cckm/aws package is not importable here, so the cm
// package defines its own.
const cmNotFoundError = "status: 404"

// HandleReadResponse centralises the error handling for the Read() methods of CM
// resources. Given the error returned by a GET call against CipherTrust Manager
// it decides whether the caller should stop processing:
//
//   - err == nil: returns false; the caller continues refreshing state.
//   - HTTP 404 (resource deleted out-of-band): the resource is removed from
//     Terraform state, a Warning diagnostic is emitted, and true is returned so
//     a subsequent `terraform plan` proposes recreating the resource.
//   - any other error: an Error diagnostic is recorded and true is returned.
//
// resourceTypeName is the Terraform type name (e.g. "ciphertrust_cm_key") used in
// the diagnostic messages.
func HandleReadResponse(ctx context.Context, err error, resp *resource.ReadResponse, resourceTypeName string) (shouldStop bool) {
	if err == nil {
		return false
	}

	if strings.Contains(err.Error(), cmNotFoundError) {
		tflog.Warn(ctx, "["+resourceTypeName+" -> Read][resource not found on CipherTrust Manager, removing from state]")
		resp.Diagnostics.AddWarning(
			"Resource removed from state",
			resourceTypeName+" no longer exists on CipherTrust Manager and has been removed from Terraform state. Run terraform plan to recreate it.",
		)
		resp.State.RemoveResource(ctx)
		return true
	}

	resp.Diagnostics.AddError(
		"Error reading "+resourceTypeName+" from CipherTrust Manager",
		"Could not read "+resourceTypeName+", unexpected error: "+err.Error(),
	)
	return true
}
