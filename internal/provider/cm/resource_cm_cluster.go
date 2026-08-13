package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &resourceCMCluster{}
	_ resource.ResourceWithConfigure      = &resourceCMCluster{}
	_ resource.ResourceWithValidateConfig = &resourceCMCluster{}

	// deleteVerifyRetries/deleteVerifyInterval bound Delete()'s post-teardown polling.
	// The budget has to outlast a CM service restart, not just the DELETE call: on 2.21.3
	// the DELETE never returned and logins were still failing 20s later, so the previous
	// 3 × 5s expired mid-restart and failed a destroy that had succeeded. Vars so tests
	// can shorten them.
	deleteVerifyRetries  = 90 // 15 minutes
	deleteVerifyInterval = 10 * time.Second

	// deleteVerifiedHealthRetries is the shorter budget for when the DELETE succeeded: CM
	// already confirmed the deletion, so this only waits for the node to serve again.
	deleteVerifiedHealthRetries = 30 // 5 minutes
)

func NewResourceCMCluster() resource.Resource {
	return &resourceCMCluster{}
}

type resourceCMCluster struct {
	client *common.Client
}

func (r *resourceCMCluster) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cluster"
}

func (r *resourceCMCluster) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_cluster", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMCluster) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Initializes a new CipherTrust Manager cluster with this node as the initial member. Additional nodes can be added using ciphertrust_cluster_node resources. **Only available on CipherTrust Manager — not supported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The cluster node ID.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"local_node_host": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) The hostname or IP of this node. Must be reachable by all nodes in the cluster, including this one.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"local_node_port": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(5432),
				Description: "(Immutable) The port of this node. Defaults to 5432.",
				PlanModifiers: []planmodifier.Int64{
					modifiers.ImmutableInt64(),
				},
			},
			"public_address": schema.StringAttribute{
				Optional:    true,
				Description: "The fully qualified domain name (FQDN) or public IP of this node. This attribute is used by CipherTrust Manager connectors to learn how to access this particular node of the cluster remotely. Can be updated.",
			},
			"node_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager node ID assigned to this cluster node.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"node_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of nodes in the cluster.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			"status_code": schema.StringAttribute{
				Computed:    true,
				Description: "Short cluster status code (e.g., 'r' = ready).",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"status_description": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable cluster status description.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"raft_status": schema.StringAttribute{
				Computed:    true,
				Description: "Raft replication status for this cluster node (e.g. 'leader', 'follower'). Populated from ClusterInfo GET response.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMCluster) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_cluster.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan CMClusterTFSDK
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build payload for POST /v1/cluster/new
	payload := NewCMClusterNodeJSON{
		LocalNodeHost: plan.LocalNodeHost.ValueString(),
		LocalNodePort: plan.LocalNodePort.ValueInt64(),
	}
	if !plan.PublicAddress.IsNull() && !plan.PublicAddress.IsUnknown() {
		payload.PublicAddress = plan.PublicAddress.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_cluster.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid payload for cluster creation",
			err.Error(),
		)
		return
	}

	// POST /v1/cluster/new
	response, err := r.client.PostDataV2(ctx, id, common.URL_NEW_CLUSTER, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_cluster.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating cluster on CipherTrust Manager",
			"Could not create cluster, unexpected error: "+err.Error(),
		)
		return
	}

	// Update state with response data
	nodeID := gjson.Get(response, "nodeID").String()
	plan.ID = types.StringValue(nodeID)
	plan.NodeId = types.StringValue(nodeID)
	plan.NodeCount = types.Int64Value(gjson.Get(response, "nodeCount").Int())
	plan.StatusCode = types.StringValue(gjson.Get(response, "status.code").String())
	plan.StatusDescription = types.StringValue(gjson.Get(response, "status.description").String())
	// ClusterJoinResponse (POST /v1/cluster/new) does not include raftStatus per swagger definition.
	// gjson returns "" — acceptable for Computed-only. Read() will populate the real value on next refresh.
	plan.RaftStatus = types.StringValue(gjson.Get(response, "raftStatus").String())

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_cluster.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMCluster) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMClusterTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_cluster.go -> Read][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_cluster.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// GET /v1/cluster — returns ClusterInfo{nodeID, status{code,description}, nodeCount, raftStatus}
	response, err := r.client.ReadDataByParam(ctx, id, "", common.URL_CLUSTER_INFO)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddError(
				fmt.Sprintf(common.NotFoundReadErrorSummaryFmt, "CM Cluster"),
				fmt.Sprintf(common.NotFoundReadErrorDetailFmt, "CM Cluster", state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_cluster.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading cluster information from CipherTrust Manager",
			"Could not read cluster info, unexpected error: "+err.Error(),
		)
		return
	}

	// GET /cluster does not 404 when this node has no cluster (e.g. it was deleted
	// out-of-band) — it returns 200 with an empty/"none" status and no nodeID instead.
	// Treat that as not-found so the next plan proposes recreating the cluster, rather
	// than silently absorbing the drift as an in-place attribute change.
	nodeID := gjson.Get(response, "nodeID").String()
	statusCode := gjson.Get(response, "status.code").String()
	if nodeID == "" || statusCode == "" || statusCode == "none" {
		resp.Diagnostics.AddWarning(
			"Cluster Not Clustered — State Preserved",
			"The Cluster is no longer active or clustered. To prevent accidental data loss, this resource has been kept in state.",
		)
		return
	}

	// Hydrate Computed fields from ClusterInfo.
	// local_node_host, local_node_port, and id are absent from ClusterInfo and are
	// preserved from prior state (loaded above via req.State.Get).
	state.NodeId = types.StringValue(nodeID)
	state.NodeCount = types.Int64Value(gjson.Get(response, "nodeCount").Int())
	state.StatusCode = types.StringValue(statusCode)
	state.StatusDescription = types.StringValue(gjson.Get(response, "status.description").String())
	state.RaftStatus = types.StringValue(gjson.Get(response, "raftStatus").String())

	// public_address is also absent from ClusterInfo — GET /nodes/{nodeID} is the only
	// endpoint that returns it (same root cause/fix as ciphertrust_cluster_node's Read()).
	// A transient fetch failure here shouldn't fail the whole Read, so leave the prior
	// state value in place rather than erroring.
	if nodeInfo, nerr := r.client.GetById(ctx, id, nodeID, common.URL_NODES); nerr == nil {
		// CM reports no publicAddress when none was ever configured. public_address is
		// Optional (not Computed), so an unconfigured attribute plans as null, not "" —
		// mapping that to StringValue("") here would permanently disagree with the null
		// and show a spurious diff on every plan.
		publicAddress := gjson.Get(nodeInfo, "publicAddress").String()
		// But when state holds an address, an empty reply is ambiguous — CM also omits the
		// field for a while after a create/join (see memberPublicAddress) — so re-check.
		if publicAddress == "" && !state.PublicAddress.IsNull() {
			if waited, waitErr := memberPublicAddress(ctx, r.client, id, nodeID); waitErr != nil {
				r.client.Log.Debug("[resource_cm_cluster.go -> Read][" + id + "] could not re-check publicAddress, keeping prior state value: " + waitErr.Error())
				publicAddress = state.PublicAddress.ValueString()
			} else {
				publicAddress = waited
			}
		}
		if publicAddress != "" {
			state.PublicAddress = types.StringValue(publicAddress)
		} else {
			state.PublicAddress = types.StringNull()
		}
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMCluster) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_cluster.go -> Update][" + id + "]")

	var plan, state CMClusterTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Only public_address is updatable
	if !plan.PublicAddress.Equal(state.PublicAddress) {
		nodeID := state.NodeId.ValueString()

		// Build PATCH payload
		updatePayload := map[string]interface{}{}
		if !plan.PublicAddress.IsNull() && !plan.PublicAddress.IsUnknown() {
			updatePayload["publicAddress"] = plan.PublicAddress.ValueString()
		} else {
			// Empty string clears the public address
			updatePayload["publicAddress"] = ""
		}

		payloadJSON, err := json.Marshal(updatePayload)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_cluster.go -> Update][" + id + "]")
			resp.Diagnostics.AddError("Invalid update payload", err.Error())
			return
		}

		// PATCH /v1/nodes/{id}
		_, err = r.client.UpdateDataV2(ctx, nodeID, common.URL_NODES, payloadJSON)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_cluster.go -> Update][" + id + "]")
			resp.Diagnostics.AddError(
				"Error updating public_address",
				"Could not update public_address for node "+nodeID+": "+err.Error(),
			)
			return
		}

		r.client.Log.Debug("[resource_cm_cluster.go -> Update] Successfully updated public_address for node " + nodeID)
	}

	// Copy plan to state
	state.PublicAddress = plan.PublicAddress

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_cluster.go -> Update][" + id + "]")
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMCluster) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMClusterTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// DELETE /v1/cluster
	// Note: This only works if this is the last/only node in the cluster
	output, err := r.client.DeleteByURL(ctx, state.NodeId.ValueString(), common.URL_CLUSTER_INFO)
	if err != nil {
		// This restarts the node's services, so it routinely errors client-side even when
		// the teardown went through (~170s timeout live, and on 2.21.3 no response at all).
		r.client.Log.Debug("[resource_cm_cluster.go -> Delete] DELETE /cluster errored (" + err.Error() + "); verifying actual cluster state")
	} else {
		r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_cluster.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
	}

	// The teardown restarts CM whether or not the DELETE returned, so wait for the node to
	// answer before returning — otherwise the next plan fails building its API client
	// (HTTP 500 from auth). After an error the node must also report itself unclustered,
	// the only evidence the teardown happened; after a 200 any answer will do, since
	// requiring "unclustered" would stall the full budget when a 200 leaves a cluster
	// behind (the endpoint only removes the last node).
	budget := deleteVerifyRetries
	if err == nil {
		budget = deleteVerifiedHealthRetries
	}
	for attempt := 1; attempt <= budget; attempt++ {
		verifyResponse, verifyErr := r.client.ReadDataByParam(ctx, state.ID.ValueString(), "", common.URL_CLUSTER_INFO)
		if verifyErr == nil {
			nodeID := gjson.Get(verifyResponse, "nodeID").String()
			statusCode := gjson.Get(verifyResponse, "status.code").String()
			if nodeID == "" || statusCode == "" || statusCode == "none" {
				r.client.Log.Debug("[resource_cm_cluster.go -> Delete] node is confirmed not clustered and serving requests again; treating as deleted")
				return
			}
			if err == nil {
				// Serving again but still clustered after an accepted DELETE: surface it
				// rather than waiting for a state that may never come.
				r.client.Log.Debug(fmt.Sprintf("[resource_cm_cluster.go -> Delete] DELETE succeeded but node still reports cluster status %q", statusCode))
				resp.Diagnostics.AddWarning(
					"Cluster deletion accepted but node still reports a cluster",
					"CipherTrust Manager accepted the deletion, but node "+state.LocalNodeHost.ValueString()+
						" still reports cluster status \""+statusCode+"\". DELETE /cluster only removes the last node of a "+
						"cluster; check the node's cluster status before creating a new cluster on it.",
				)
				return
			}
			// Teardown may still be in flight; a mid-teardown status is not evidence that
			// the delete failed, so keep waiting.
			r.client.Log.Debug(fmt.Sprintf("[resource_cm_cluster.go -> Delete] node still reports cluster status %q (attempt %d/%d)", statusCode, attempt, budget))
		} else {
			if strings.Contains(verifyErr.Error(), "status: 401") {
				// Token expired while the node was restarting.
				if refreshErr := r.client.RefreshToken(ctx, state.ID.ValueString()); refreshErr != nil {
					r.client.Log.Debug("[resource_cm_cluster.go -> Delete] token refresh failed: " + refreshErr.Error())
				}
			}
			r.client.Log.Debug(fmt.Sprintf("[resource_cm_cluster.go -> Delete] node not answering yet (attempt %d/%d): %s", attempt, budget, verifyErr.Error()))
		}
		if attempt < budget {
			time.Sleep(deleteVerifyInterval)
		}
	}

	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting cluster",
			err.Error(),
		)
		return
	}
	// The DELETE was accepted, so the cluster is gone as far as CM is concerned; only the
	// post-teardown health check timed out. Warn rather than failing a destroy over it.
	resp.Diagnostics.AddWarning(
		"Cluster deleted but node did not report back",
		"CipherTrust Manager accepted the cluster deletion, but node "+state.LocalNodeHost.ValueString()+
			" did not answer within the verification window. It may still be restarting; "+
			"check its cluster status before creating a new cluster on it.",
	)
}

func (d *resourceCMCluster) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	d.client = client
}

// extractHost extracts the bare hostname or IP from either a plain hostname/IP
// string or a URL string (e.g. "https://1.2.3.4/" or "https://cm.example.com").
// Both IP addresses and FQDNs are accepted as bare values.
func extractHost(input string) (string, error) {
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil {
			return "", fmt.Errorf("invalid URL %q: %w", input, err)
		}
		return u.Hostname(), nil
	}
	// Bare IP address.
	if net.ParseIP(input) != nil {
		return input, nil
	}
	// Bare hostname — non-empty is sufficient; the API will reject invalid values.
	if input != "" {
		return input, nil
	}
	return "", fmt.Errorf("host must not be empty")
}
