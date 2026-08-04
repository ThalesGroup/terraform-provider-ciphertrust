package common

// Standard diagnostic messages for 404 (not found) responses from CipherTrust Manager.
//
// Read / Update 404 — emit AddError, preserve state.
// Rationale: a 404 during Read or Update is unexpected; the resource was known to exist
// in state. Surfacing it as an error prevents silent drift and forces the operator to
// decide whether to run `terraform state rm` or recreate the resource.
//
// Delete 404 — emit AddWarning, let Delete return normally so Terraform removes from state.
// Rationale: if the resource is already gone the desired state (absent) is achieved;
// there is nothing more to do, and an error would leave a phantom in state.

// NotFoundReadErrorSummaryFmt is the summary string for AddError when a resource
// returns HTTP 404 during a Read or Update operation.
// The %s placeholder receives the human-readable resource type (e.g. "AWS Connection").
const NotFoundReadErrorSummaryFmt = "%s Not Found on CipherTrust Manager"

// NotFoundReadErrorDetailFmt is the detail string for AddError when a resource
// returns HTTP 404 during a Read or Update operation.
// Placeholders (in order): resource type string, resource ID.
const NotFoundReadErrorDetailFmt = "The %s resource with ID %q was not found (HTTP 404). " +
	"To prevent accidental data loss the resource has been retained in Terraform state. " +
	"If it was permanently deleted outside of Terraform, remove it from state with: " +
	"'terraform state rm <resource_address>'. " +
	"Terraform will attempt to recreate it on the next apply if it remains in the configuration."

// NotFoundDeleteWarningSummary is the summary string for AddWarning when a resource
// returns HTTP 404 during a Delete operation.
const NotFoundDeleteWarningSummary = "Resource Not Found During Deletion — Removed from State"

// NotFoundDeleteWarningDetail is the detail string for AddWarning when a resource
// returns HTTP 404 during a Delete operation.
const NotFoundDeleteWarningDetail = "The resource was not found on CipherTrust Manager (HTTP 404) during deletion. " +
	"It was likely removed outside of Terraform. " +
	"Treating as successfully deleted and removing from Terraform state."
