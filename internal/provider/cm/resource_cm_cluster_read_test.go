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
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_CM_ClusterRead_NotClusteredRemovesResource proves that Read() now treats an
// out-of-band cluster deletion as a missing resource. GET /v1/cluster never 404s —
// a node with no cluster still returns 200 with an empty/"none" status and no nodeID.
// Before the fix, Read() only checked for a literal 404 (which this endpoint never
// returns) and otherwise hydrated the "not clustered" body as if it were a normal
// attribute change, so the resource was never recreated.
func Test_CM_ClusterRead_NotClusteredRemovesResource(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cluster", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"nodeID":"","status":{"code":"none","description":"not clustered"},"nodeCount":0}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMCluster{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	rawState := tftypes.NewValue(stateType, map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, "b3c23d5"),
		"local_node_host":    tftypes.NewValue(tftypes.String, "cm1.example.com"),
		"local_node_port":    tftypes.NewValue(tftypes.Number, 5432),
		"public_address":     tftypes.NewValue(tftypes.String, nil),
		"node_id":            tftypes.NewValue(tftypes.String, "b3c23d5"),
		"node_count":         tftypes.NewValue(tftypes.Number, 1),
		"status_code":        tftypes.NewValue(tftypes.String, "r"),
		"status_description": tftypes.NewValue(tftypes.String, "ready"),
		"raft_status":        tftypes.NewValue(tftypes.String, "up"),
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
	if !resp.State.Raw.IsNull() {
		t.Fatalf("expected Read() to remove the resource from state when cluster is not clustered, but state is still set: %#v", resp.State.Raw)
	}
}

// Test_CM_ClusterRead_PublicAddressDrift proves that Read() now surfaces public_address
// drift for ciphertrust_cluster. Before the fix, Read() preserved public_address
// unconditionally from prior state — GET /v1/cluster (ClusterInfo) never returns it, and
// nothing else in Read() re-fetched it — so a real out-of-band change made directly via
// PATCH /v1/nodes/{id} was never reflected back into state on refresh. Mirrors the
// analogous fix/test for ciphertrust_cluster_node (Test_CM_ClusterNodeRead_PublicAddressDrift).
func Test_CM_ClusterRead_PublicAddressDrift(t *testing.T) {
	const nodeID = "b3c23d5"
	const oldPublicAddress = "10.171.29.61-valid-update"
	const newPublicAddress = "10.171.29.61-oob-change"

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/cluster/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"nodeID":%q,"nodeCount":1,"status":{"code":"r","description":"ready"},"raftStatus":"up"}`, nodeID)
	})
	mux.HandleFunc("/api/v1/nodes/"+nodeID, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%q,"publicAddress":%q}`, nodeID, newPublicAddress)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMCluster{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	rawState := tftypes.NewValue(stateType, map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, nodeID),
		"local_node_host":    tftypes.NewValue(tftypes.String, "cm1.example.com"),
		"local_node_port":    tftypes.NewValue(tftypes.Number, 5432),
		"public_address":     tftypes.NewValue(tftypes.String, oldPublicAddress),
		"node_id":            tftypes.NewValue(tftypes.String, nodeID),
		"node_count":         tftypes.NewValue(tftypes.Number, 1),
		"status_code":        tftypes.NewValue(tftypes.String, "r"),
		"status_description": tftypes.NewValue(tftypes.String, "ready"),
		"raft_status":        tftypes.NewValue(tftypes.String, "up"),
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

	var final CMClusterTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}

	if got := final.PublicAddress.ValueString(); got != newPublicAddress {
		t.Errorf("public_address drift not detected: got %q, want %q (stale value %q should have been overwritten)",
			got, newPublicAddress, oldPublicAddress)
	}
}

// Test_CM_ClusterDelete_TimeoutButActuallyDeletedSucceeds proves that Delete() no longer
// surfaces a hard error when DELETE /cluster itself errors (e.g. times out) but the node
// has actually become unclustered. Confirmed live: deleting a node's own cluster config
// can make its management service briefly unresponsive while it tears down its local
// raft/postgres processes, timing out the DELETE call client-side even though the
// server-side change already went through (a GET /cluster immediately after showed
// status.code="none" — already deleted).
func Test_CM_ClusterDelete_TimeoutButActuallyDeletedSucceeds(t *testing.T) {
	orig := deleteVerifyInterval
	deleteVerifyInterval = time.Millisecond
	t.Cleanup(func() { deleteVerifyInterval = orig })

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusGatewayTimeout)
			fmt.Fprint(w, `{"code":14,"codeDesc":"context deadline exceeded"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"nodeID":"","status":{"code":"none","description":"not clustered"}}`)
	}
	mux := http.NewServeMux()
	// DeleteByURL requests the bare path ("/api/v1/cluster"); the verify GET this fix
	// adds goes through ReadDataByParam with an empty id, which appends a trailing
	// slash ("/api/v1/cluster/") — register both so the fake server matches either.
	mux.HandleFunc("/api/v1/cluster", handler)
	mux.HandleFunc("/api/v1/cluster/", handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMCluster{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	rawState := tftypes.NewValue(stateType, map[string]tftypes.Value{
		"id":                 tftypes.NewValue(tftypes.String, "e572ff7"),
		"local_node_host":    tftypes.NewValue(tftypes.String, "cm1.example.com"),
		"local_node_port":    tftypes.NewValue(tftypes.Number, 5432),
		"public_address":     tftypes.NewValue(tftypes.String, nil),
		"node_id":            tftypes.NewValue(tftypes.String, "e572ff7"),
		"node_count":         tftypes.NewValue(tftypes.Number, 1),
		"status_code":        tftypes.NewValue(tftypes.String, "r"),
		"status_description": tftypes.NewValue(tftypes.String, "ready"),
		"raft_status":        tftypes.NewValue(tftypes.String, "up"),
	})

	req := resource.DeleteRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}
	resp := &resource.DeleteResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}

	r.Delete(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("expected Delete() to succeed after verifying the node is actually unclustered, got diagnostics: %v", resp.Diagnostics)
	}
}
