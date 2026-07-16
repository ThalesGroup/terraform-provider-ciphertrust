package cm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

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
