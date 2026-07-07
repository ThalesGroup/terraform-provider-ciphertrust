package common

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ValidateCMOnly emits a plan-time error if the resource is being used against
// a CDSPaaS deployment. Resources that manage CipherTrust Manager
// infrastructure or features (cluster, domain, network interfaces, NTP,
// syslog, licensing, HSM root-of-trust, proxy, Prometheus, password policy,
// policies, policy attachments, system properties, SCP connections) are
// platform-managed in CDSPaaS and not exposed to tenants; they should fail at
// plan time rather than producing a confusing 4xx at apply time.
//
// Call from a resource's ValidateConfig method:
//
//	func (r *resourceFoo) ValidateConfig(ctx context.Context,
//	    req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
//	    common.ValidateCMOnly(ctx, r.client, "ciphertrust_foo", resp)
//	}
//
// The framework guarantees Configure runs before ValidateConfig, so r.client
// is populated. The nil check here covers terraform validate (which skips
// Configure) and the framework's first-pass validation.
func ValidateCMOnly(_ context.Context, client *Client, resourceName string, resp *resource.ValidateConfigResponse) {
	if client == nil {
		return
	}
	if !client.IsCDSPaaS {
		return
	}
	resp.Diagnostics.AddError(
		"Resource not supported on CDSPaaS",
		resourceName+" manages CipherTrust Manager infrastructure that is "+
			"platform-managed in CDSPaaS. Remove this resource or "+
			"target an on-prem CipherTrust Manager instance.",
	)
}
