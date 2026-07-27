package cm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_CM_ClusterNodeSchema_ComputedFieldsUseStateForUnknown guards against the same
// bug fixed on ciphertrust_cluster's raft_status: a Computed attribute with no
// UseStateForUnknown() can get marked unknown on a plan where anything else on the
// resource differs, producing a spurious diff unrelated to the field itself.
// node_count/status_code/status_description lacked it; id and node_id already had it.
func Test_CM_ClusterNodeSchema_ComputedFieldsUseStateForUnknown(t *testing.T) {
	r := &resourceCMClusterNode{}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	// nonNullRawState is a minimal non-null tftypes.Value used only to satisfy
	// UseStateForUnknown()'s req.State.Raw.IsNull() check (added in
	// terraform-plugin-framework v1.14+; previously it checked req.StateValue.IsNull()
	// instead). It does not need to match the resource's real schema type — the plan
	// modifier only tests for "is there any prior state at all" (Create vs. Update).
	nonNullRawState := tfsdk.State{
		Raw: tftypes.NewValue(
			tftypes.Object{AttributeTypes: map[string]tftypes.Type{"placeholder": tftypes.String}},
			map[string]tftypes.Value{"placeholder": tftypes.NewValue(tftypes.String, "x")},
		),
	}

	t.Run("node_count", func(t *testing.T) {
		attr, ok := schemaResp.Schema.Attributes["node_count"].(schema.Int64Attribute)
		if !ok {
			t.Fatalf("node_count is not a schema.Int64Attribute")
		}
		if len(attr.PlanModifiers) == 0 {
			t.Fatal("node_count has no plan modifiers — an unconfigured Computed-only " +
				"attribute will be marked unknown on every plan, causing a perpetual " +
				"non-empty refresh plan even when nothing changed")
		}
		req := planmodifier.Int64Request{
			State:       nonNullRawState,
			StateValue:  types.Int64Value(2),
			PlanValue:   types.Int64Unknown(),
			ConfigValue: types.Int64Null(),
		}
		var resp planmodifier.Int64Response
		resp.PlanValue = req.PlanValue
		attr.PlanModifiers[0].PlanModifyInt64(ctx, req, &resp)
		if !resp.PlanValue.Equal(types.Int64Value(2)) {
			t.Errorf("expected plan modifier to carry forward the known state value 2 "+
				"into the unknown plan value, got %v", resp.PlanValue)
		}
	})

	for _, name := range []string{"status_code", "status_description"} {
		name := name
		t.Run(name, func(t *testing.T) {
			attr, ok := schemaResp.Schema.Attributes[name].(schema.StringAttribute)
			if !ok {
				t.Fatalf("%s is not a schema.StringAttribute", name)
			}
			if len(attr.PlanModifiers) == 0 {
				t.Fatalf("%s has no plan modifiers — an unconfigured Computed-only "+
					"attribute will be marked unknown on every plan, causing a perpetual "+
					"non-empty refresh plan even when nothing changed", name)
			}
			req := planmodifier.StringRequest{
				State:       nonNullRawState,
				StateValue:  types.StringValue("r"),
				PlanValue:   types.StringUnknown(),
				ConfigValue: types.StringNull(),
			}
			var resp planmodifier.StringResponse
			resp.PlanValue = req.PlanValue
			attr.PlanModifiers[0].PlanModifyString(ctx, req, &resp)
			if !resp.PlanValue.Equal(types.StringValue("r")) {
				t.Errorf("expected plan modifier to carry forward the known state value "+
					"\"r\" into the unknown plan value, got %v", resp.PlanValue)
			}
		})
	}
}

// Test_CM_ClusterNodeRead_PublicAddressDrift is an end-to-end unit test proving that
// Read() now surfaces public_address drift. Before the fix, Read() only talked to the
// joining node's own GET /v1/cluster endpoint (which never returns publicAddress), so
// a public_address change made via Update() (PATCH api/v1/nodes/{id} on the cluster
// member) was never reflected back into state on a subsequent refresh.
//
// Two fake servers are required because Read() genuinely uses two different clients:
//  1. nodeServer stands in for the joining node itself: it must handle the SignIn
//     POST (common.NewClient dials it) and GET api/v1/cluster (common.URL_CLUSTER_INFO).
//  2. memberServer stands in for the cluster member (r.client, the resource's own
//     already-configured client): it must handle GET api/v1/nodes/{nodeID}, which is
//     the only endpoint that actually returns publicAddress.
func Test_CM_ClusterNodeRead_PublicAddressDrift(t *testing.T) {
	const nodeID = "n1"
	const newPublicAddress = "10.171.30.99"
	const oldPublicAddress = "10.171.20.1"

	// Fake joining node: auth + GET api/v1/cluster.
	nodeMux := http.NewServeMux()
	nodeMux.HandleFunc("/api/v1/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jwt":"fake-node-token","refresh_token":"fake-refresh"}`)
	})
	nodeMux.HandleFunc("/api/v1/cluster", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"nodeID":%q,"nodeCount":2,"status":{"code":"r","description":"ready"}}`, nodeID)
	})
	nodeServer := httptest.NewServer(nodeMux)
	defer nodeServer.Close()

	// Fake cluster member: GET api/v1/nodes/{nodeID} -> publicAddress.
	memberMux := http.NewServeMux()
	memberMux.HandleFunc("/api/v1/nodes/"+nodeID, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"publicAddress":%q}`, nodeID, newPublicAddress)
	})
	memberServer := httptest.NewServer(memberMux)
	defer memberServer.Close()

	client := &common.Client{
		CipherTrustURL: memberServer.URL,
		HTTPClient:     memberServer.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMClusterNode{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	credentialsType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"address":       tftypes.String,
			"username":      tftypes.String,
			"password":      tftypes.String,
			"domain":        tftypes.String,
			"auth_domain":   tftypes.String,
			"no_ssl_verify": tftypes.Bool,
		},
	}

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	rawState := tftypes.NewValue(stateType, map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, nodeID),
		"host":               tftypes.NewValue(tftypes.String, "joining-node.example.com"),
		"port":               tftypes.NewValue(tftypes.Number, 5432),
		"public_address":     tftypes.NewValue(tftypes.String, oldPublicAddress),
		"member_host":        tftypes.NewValue(tftypes.String, nil),
		"member_port":        tftypes.NewValue(tftypes.Number, 5432),
		"node_id":            tftypes.NewValue(tftypes.String, nodeID),
		"node_count":         tftypes.NewValue(tftypes.Number, 1),
		"status_code":        tftypes.NewValue(tftypes.String, "r"),
		"status_description": tftypes.NewValue(tftypes.String, "ready"),
		"credentials": tftypes.NewValue(credentialsType, map[string]tftypes.Value{
			// credentials.address (not host) is what Read() actually dials, so
			// point it at the fake joining-node server.
			"address":       tftypes.NewValue(tftypes.String, nodeServer.URL),
			"username":      tftypes.NewValue(tftypes.String, "admin"),
			"password":      tftypes.NewValue(tftypes.String, "password"),
			"domain":        tftypes.NewValue(tftypes.String, ""),
			"auth_domain":   tftypes.NewValue(tftypes.String, ""),
			"no_ssl_verify": tftypes.NewValue(tftypes.Bool, true),
		}),
	})

	req := resource.ReadRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}

	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Read(): %v", resp.Diagnostics)
	}

	var final CMAddClusterNodeTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}

	if got := final.PublicAddress.ValueString(); got != newPublicAddress {
		t.Errorf("public_address drift not detected: got %q, want %q (stale value %q should have been overwritten)",
			got, newPublicAddress, oldPublicAddress)
	}
}

// newClusterNodeReadTestResource builds a resourceCMClusterNode against two independent
// fake servers — nodeServer stands in for the joining node itself (self-reported
// status.code), memberHandler controls the cluster member's GET api/v1/nodes/{id}
// response (the authoritative membership signal) — and runs Read(). Used by the
// removal-detection tests below. Mirrors the two-server split documented on
// Test_CM_ClusterNodeRead_PublicAddressDrift: Read() genuinely talks to two distinct
// clients (nodeClient via credentials.address, r.client the resource's own client).
func newClusterNodeReadTestResource(t *testing.T, selfNodeID, statusCode, statusDesc string, memberHandler http.HandlerFunc) *resource.ReadResponse {
	t.Helper()
	nodeID := selfNodeID
	// stateNodeID is what the prior Terraform state records; Read() reports whatever
	// the joining node self-reports (possibly a blanked-out nodeID), independent of it.
	const stateNodeID = "n1"

	nodeMux := http.NewServeMux()
	nodeMux.HandleFunc("/api/v1/auth/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jwt":"fake-node-token","refresh_token":"fake-refresh"}`)
	})
	nodeMux.HandleFunc("/api/v1/cluster", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"nodeID":%q,"nodeCount":1,"status":{"code":%q,"description":%q}}`, nodeID, statusCode, statusDesc)
	})
	nodeServer := httptest.NewServer(nodeMux)
	t.Cleanup(nodeServer.Close)

	memberMux := http.NewServeMux()
	memberMux.HandleFunc("/api/v1/nodes/"+nodeID, memberHandler)
	memberServer := httptest.NewServer(memberMux)
	t.Cleanup(memberServer.Close)

	client := &common.Client{
		CipherTrustURL: memberServer.URL,
		HTTPClient:     memberServer.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMClusterNode{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	credentialsType := tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"address":       tftypes.String,
			"username":      tftypes.String,
			"password":      tftypes.String,
			"domain":        tftypes.String,
			"auth_domain":   tftypes.String,
			"no_ssl_verify": tftypes.Bool,
		},
	}

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	rawState := tftypes.NewValue(stateType, map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, stateNodeID),
		"host":               tftypes.NewValue(tftypes.String, "joining-node.example.com"),
		"port":               tftypes.NewValue(tftypes.Number, 5432),
		"public_address":     tftypes.NewValue(tftypes.String, "10.171.30.25"),
		"member_host":        tftypes.NewValue(tftypes.String, nil),
		"member_port":        tftypes.NewValue(tftypes.Number, 5432),
		"node_id":            tftypes.NewValue(tftypes.String, stateNodeID),
		"node_count":         tftypes.NewValue(tftypes.Number, 3),
		"status_code":        tftypes.NewValue(tftypes.String, "r"),
		"status_description": tftypes.NewValue(tftypes.String, "ready"),
		"credentials": tftypes.NewValue(credentialsType, map[string]tftypes.Value{
			"address":       tftypes.NewValue(tftypes.String, nodeServer.URL),
			"username":      tftypes.NewValue(tftypes.String, "admin"),
			"password":      tftypes.NewValue(tftypes.String, "password"),
			"domain":        tftypes.NewValue(tftypes.String, ""),
			"auth_domain":   tftypes.NewValue(tftypes.String, ""),
			"no_ssl_verify": tftypes.NewValue(tftypes.Bool, true),
		}),
	})

	req := resource.ReadRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}

	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Read(): %v", resp.Diagnostics)
	}
	return resp
}

// Test_CM_ClusterNodeRead_RemovedNodeRemovesResource proves that Read() now detects an
// out-of-band node removal via the cluster member's own node list (GET /nodes/{id}
// erroring, e.g. 404/500 — confirmed live against a real CM: an out-of-band-removed
// node's ID returns HTTP 500 from the member, same as a never-existed ID) and calls
// RemoveResource. Deliberately gives the joining node itself a "down" self-report —
// confirmed live that a removed node settles at status.code="d", NOT a distinct
// removed/removing code — to prove detection does not depend on that self-report.
func Test_CM_ClusterNodeRead_RemovedNodeRemovesResource(t *testing.T) {
	orig := memberCheckInterval
	memberCheckInterval = time.Millisecond
	t.Cleanup(func() { memberCheckInterval = orig })

	resp := newClusterNodeReadTestResource(t, "n1", nodeStatusDown, "down", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"code":14,"codeDesc":"NCERRInternalServerError: unexpected error"}`)
	})
	if !resp.State.Raw.IsNull() {
		t.Fatalf("expected Read() to remove the resource when the cluster member no longer lists this node, but state is still set: %#v", resp.State.Raw)
	}
}

// Test_CM_ClusterNodeRead_EmptyNodeIDRemovesResource proves that Read() detects a node
// that has fully settled after out-of-band removal — confirmed live that such a node
// resets to the exact same blank nodeID/"none" status a never-clustered node reports —
// and removes it directly, without depending on the member-check call. This matters
// because GetById with an empty id resolves to ".../nodes/" (the list endpoint), which
// succeeds and would otherwise silently defeat the member-check (this was caught live:
// the first version of this fix fell through to hydrating state from the list response).
func Test_CM_ClusterNodeRead_EmptyNodeIDRemovesResource(t *testing.T) {
	resp := newClusterNodeReadTestResource(t, "", "none", "not clustered", func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("member should not be queried when the joining node reports an empty nodeID")
	})
	if !resp.State.Raw.IsNull() {
		t.Fatalf("expected Read() to remove the resource for an empty self-reported nodeID, but state is still set: %#v", resp.State.Raw)
	}
}

// Test_CM_ClusterNodeRead_StillMemberKeepsResource proves the fix does NOT treat a node's
// own transient "down" status.code as removal by itself: as long as the cluster member's
// node list still recognizes this node, Read() must keep hydrating state as today. "down"/
// "killed" are also the codes a node reports during its normal transient reboot right
// after joining (see nodeIsJoining/Create), or an ordinary OS reboot well after joining;
// getting this wrong would turn a brief reboot into a false recreate, which for this
// resource means a real multi-minute cluster rejoin.
func Test_CM_ClusterNodeRead_StillMemberKeepsResource(t *testing.T) {
	const newPublicAddress = "10.171.97.99"
	resp := newClusterNodeReadTestResource(t, "n1", nodeStatusDown, "down", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"nodeID":"n1","publicAddress":%q}`, newPublicAddress)
	})
	if resp.State.Raw.IsNull() {
		t.Fatalf("Read() removed the resource even though the cluster member still lists this node; a transient status.code=%q must not trigger removal", nodeStatusDown)
	}

	var final CMAddClusterNodeTFSDK
	diags := resp.State.Get(context.Background(), &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if got := final.StatusCode.ValueString(); got != nodeStatusDown {
		t.Errorf("status_code not hydrated: got %q, want %q", got, nodeStatusDown)
	}
	if got := final.PublicAddress.ValueString(); got != newPublicAddress {
		t.Errorf("public_address not hydrated: got %q, want %q", got, newPublicAddress)
	}
}
