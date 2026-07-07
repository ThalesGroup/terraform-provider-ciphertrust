package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Node status codes returned by GET /v1/cluster on the joining node.
const (
	nodeStatusReady                = "r"
	nodeStatusJoiningCreating      = "creating"
	nodeStatusJoiningBootstrapping = "b"
	nodeStatusJoiningSyncing       = "i"
	nodeStatusJoiningCatchingUp    = "c"
	nodeStatusJoiningCompleting    = "o"
	nodeStatusDown                 = "d"
	nodeStatusKilled               = "k"
	nodeStatusRemoving             = "m"
	nodeStatusRemoved              = "v"
)

// nodeIsJoining returns true for any in-progress joining state.
func nodeIsJoining(code string) bool {
	switch code {
	case nodeStatusJoiningCreating, nodeStatusJoiningBootstrapping,
		nodeStatusJoiningSyncing, nodeStatusJoiningCatchingUp,
		nodeStatusJoiningCompleting:
		return true
	}
	return false
}

var (
	_ resource.Resource              = &resourceCMClusterNode{}
	_ resource.ResourceWithConfigure = &resourceCMClusterNode{}

	// clusterJoinMu ensures only one node joins or leaves the cluster at a time.
	// Parallel joins/removals can break Raft consensus.
	clusterJoinMu sync.Mutex
)

func NewResourceCMClusterNode() resource.Resource {
	return &resourceCMClusterNode{}
}

type resourceCMClusterNode struct {
	client *common.Client
}

func (r *resourceCMClusterNode) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cluster_node"
}

func (r *resourceCMClusterNode) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Adds a single node to an existing CipherTrust Manager cluster. The provider's configured address is used as the existing cluster member for signing the join request.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"host": schema.StringAttribute{
				Required:    true,
				Description: "Hostname or IP address of the node to add to the cluster.",
			},
			"port": schema.Int64Attribute{
				Required:    true,
				Description: "Port of the node to add, typically 5432.",
			},
			"public_address": schema.StringAttribute{
				Required:    true,
				Description: "FQDN or public IP of the new node. Used by CipherTrust Manager connectors to reach this node remotely.",
			},
			"credentials": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Credentials for the new node. If omitted, the provider's configured credentials are used.",
				Attributes: map[string]schema.Attribute{
					"address": schema.StringAttribute{
						Required:    true,
						Description: "Address Terraform uses to connect to the joining node (e.g. public FQDN, public IP, or any reachable endpoint). Allows host to hold a private/internal address for CM API payloads while Terraform connects via a different endpoint.",
					},
					"username": schema.StringAttribute{
						Optional:    true,
						Description: "Username for the new node.",
					},
					"password": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Password for the new node.",
					},
					"domain": schema.StringAttribute{
						Optional:    true,
						Description: "CipherTrust domain to log in to on the new node. Default is the root domain.",
					},
					"auth_domain": schema.StringAttribute{
						Optional:    true,
						Description: "CipherTrust authentication domain of the user on the new node.",
					},
					"no_ssl_verify": schema.BoolAttribute{
						Optional:    true,
						Description: "Set to false to verify the server's certificate chain and host name.",
					},
				},
			},
			"member_host": schema.StringAttribute{
				Optional:    true,
				Description: "Hostname or FQDN of any existing cluster member to join through. Can be any node already in the cluster, not necessarily the first/original node. If omitted, the provider's configured address is used. Use an FQDN (e.g. ec2-1-2-3-4.compute-1.amazonaws.com) to match the member node's TLS certificate.",
			},
			"member_port": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(5432),
				Description: "Port of the existing cluster member (the provider's configured node). Defaults to 5432.",
			},
			"node_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager node ID assigned to the new node after joining the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"node_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of nodes in the cluster after this node has joined.",
			},
			"status_code": schema.StringAttribute{
				Computed:    true,
				Description: "Short cluster status code (e.g. 'r' = ready).",
			},
			"status_description": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable cluster status description.",
			},
		},
	}
}

// Create joins a new node to the existing cluster using the three-step CSR workflow.
func (r *resourceCMClusterNode) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_cluster_node.go -> Create]["+id+"]")

	var plan CMAddClusterNodeTFSDK
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	nodeHost := plan.Host.ValueString()
	tflog.Info(ctx, fmt.Sprintf("[%s] [resource_cm_cluster_node.go -> Create] ATTEMPTING to acquire cluster join lock at %v", nodeHost, time.Now()))
	clusterJoinMu.Lock()
	tflog.Info(ctx, fmt.Sprintf("[%s] [resource_cm_cluster_node.go -> Create] LOCK ACQUIRED at %v, proceeding with node join", nodeHost, time.Now()))
	defer func() {
		clusterJoinMu.Unlock()
		tflog.Info(ctx, fmt.Sprintf("[%s] [resource_cm_cluster_node.go -> Create] LOCK RELEASED at %v", nodeHost, time.Now()))
	}()

	// Snapshot member's current node count. After the joining node reports ready, we will
	// hold the semaphore until the member also reflects the updated count and status=r,
	// ensuring consensus has fully settled before the next node attempts to join.
	initialMemberNodeCount := int64(-1)
	if memberStatusBefore, memberErr := r.client.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO); memberErr == nil {
		initialMemberNodeCount = gjson.Get(memberStatusBefore, "nodeCount").Int()
		tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Member node count before join: %d", initialMemberNodeCount))
	} else {
		tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Could not read member node count before join (will poll for status=r only): %s", memberErr.Error()))
	}

	joiningNodeHost, err := extractHost(plan.Host.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid host for joining node", err.Error())
		return
	}
	joiningNodePubAddress, err := extractHost(plan.PublicAddress.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid public_address for joining node", err.Error())
		return
	}

	// Use node-specific credentials if provided, otherwise fall back to the provider's credentials.
	nodeUsername := r.client.AuthData.Username
	nodePassword := r.client.AuthData.Password
	nodeDomain := r.client.AuthData.Domain
	nodeAuthDomain := r.client.AuthData.AuthDomain
	if plan.Creds != nil {
		if !plan.Creds.Username.IsNull() && !plan.Creds.Username.IsUnknown() {
			nodeUsername = plan.Creds.Username.ValueString()
		}
		if !plan.Creds.Password.IsNull() && !plan.Creds.Password.IsUnknown() {
			nodePassword = plan.Creds.Password.ValueString()
		}
		if !plan.Creds.Domain.IsNull() && !plan.Creds.Domain.IsUnknown() {
			nodeDomain = plan.Creds.Domain.ValueString()
		}
		if !plan.Creds.AuthDomain.IsNull() && !plan.Creds.AuthDomain.IsUnknown() {
			nodeAuthDomain = plan.Creds.AuthDomain.ValueString()
		}
	}

	// credentials.address is the endpoint Terraform uses to connect to the joining node.
	// This allows host to hold a private/internal address for CM API payloads while
	// Terraform connects via a public FQDN or alternate reachable endpoint.
	nodeConnAddr := joiningNodeHost
	if plan.Creds != nil && !plan.Creds.Address.IsNull() && !plan.Creds.Address.IsUnknown() {
		if addr := plan.Creds.Address.ValueString(); addr != "" {
			nodeConnAddr = addr
		}
	}
	nodeURL := nodeConnAddr
	if !strings.Contains(nodeURL, "://") {
		nodeURL = "https://" + nodeURL
	}
	// Joining nodes present their self-signed bootstrap certificate during the
	// CSR exchange; certificate verification is not applicable until after the
	// node has been issued a cluster-trusted cert.
	nodeTLS := common.TLSOptions{InsecureSkipVerify: true}
	nodeClient, err := common.NewClient(ctx, id, &nodeURL, &nodeAuthDomain, &nodeDomain, &nodeUsername, &nodePassword, nil, nodeTLS, 180)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_cluster_node.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Unable to create HTTPS client for the joining node.", err.Error())
		return
	}

	// Step 1: Generate a CSR on the joining node.
	payloadCSR := NewCSRJSON{
		LocalNodeHost: joiningNodeHost,
		PublicAddress: joiningNodePubAddress,
	}
	payloadCSRJSON, err := json.Marshal(payloadCSR)
	if err != nil {
		resp.Diagnostics.AddError("Invalid payload: Create CSR", err.Error())
		return
	}
	responseCSR, err := nodeClient.PostDataV2(ctx, id, common.URL_CREATE_CSR, payloadCSRJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_cluster_node.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error creating CSR on the joining node: ", err.Error())
		return
	}

	// Step 2: Sign the CSR on the existing cluster member (provider's configured node).
	// Retry when consensus is temporarily unavailable after a recent node join.
	payloadSignCSR := SignRequestJSON{
		CSR:                gjson.Get(responseCSR, "csr").String(),
		NewNodeHost:        joiningNodeHost,
		PublicAddress:      joiningNodePubAddress,
		SharedHSMPartition: false,
	}
	payloadSignCSRJSON, err := json.Marshal(payloadSignCSR)
	if err != nil {
		resp.Diagnostics.AddError("Invalid payload: Sign CSR", err.Error())
		return
	}

	maxSignRetries := 180 // up to 30 minutes
	signRetryInterval := 10 * time.Second
	var responseSignCSR string
	for attempt := 1; attempt <= maxSignRetries; attempt++ {
		responseSignCSR, err = r.client.PostDataV2(ctx, id, common.URL_SIGN_CERT, payloadSignCSRJSON)
		if err == nil {
			break
		}
		if strings.Contains(err.Error(), "consensus is down") && attempt < maxSignRetries {
			tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create][%s] Consensus not ready, retrying sign CSR (attempt %d/%d)...", id, attempt, maxSignRetries))
			time.Sleep(signRetryInterval)
			continue
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_cluster_node.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error signing CSR on the existing cluster member: ", err.Error())
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Error signing CSR on the existing cluster member after retries: ", err.Error())
		return
	}

	// Step 3: Send the join request to the new node with the signed certificate and CA chain.
	// Use the explicit member_host if provided, otherwise fall back to the provider's address.
	memberHostInput := r.client.CipherTrustURL
	if !plan.MemberHost.IsNull() && plan.MemberHost.ValueString() != "" {
		memberHostInput = plan.MemberHost.ValueString()
	}
	memberHost, err := extractHost(memberHostInput)
	if err != nil {
		resp.Diagnostics.AddError("Invalid member_host for cluster member", err.Error())
		return
	}
	payloadJoinNode := JoinClusterJSON{
		CAChain:                gjson.Get(responseSignCSR, "cachain").String(),
		Cert:                   gjson.Get(responseSignCSR, "cert").String(),
		MKEKBlob:               gjson.Get(responseSignCSR, "mkek_blob").String(),
		LocalNodeHost:          joiningNodeHost,
		MemberNodeHost:         memberHost,
		MemberNodePort:         plan.MemberPort.ValueInt64(),
		LocalNodePort:          plan.Port.ValueInt64(),
		LocalNodePublicAddress: joiningNodePubAddress,
		Blocking:               false, // Use async join with status polling
	}
	payloadJoinNodeJSON, err := json.Marshal(payloadJoinNode)
	if err != nil {
		resp.Diagnostics.AddError("Invalid payload: Join Node", err.Error())
		return
	}
	responseJoinNode, err := nodeClient.PostDataV2(ctx, id, common.URL_CLUSTER_JOIN, payloadJoinNodeJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_cluster_node.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error joining cluster: ", err.Error())
		return
	}

	// Extract initial node ID from join response
	nodeID := gjson.Get(responseJoinNode, "nodeID").String()
	tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Join request initiated for node %s, polling for completion...", nodeID))

	// Poll cluster status until node is ready
	maxPollRetries := 720 // 120 minutes total
	pollInterval := 10 * time.Second

	// seenJoining becomes true once the node enters any in-progress joining state
	// (creating/bootstrapping/syncing/catching-up/completing). A "d" or "k" before
	// any joining state is a transient restart right after the async join request;
	// the same codes after joining has started are genuine failures.
	seenJoining := false

	var finalStatusResponse string
	for attempt := 1; attempt <= maxPollRetries; attempt++ {
		statusResponse, err := nodeClient.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO)
		if err != nil {
			if strings.Contains(err.Error(), "status: 401") {
				if refreshErr := nodeClient.RefreshToken(ctx, id); refreshErr == nil {
					tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Re-authenticated joining node client after token expiry (attempt %d/%d)", attempt, maxPollRetries))
				} else {
					tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Failed to re-authenticate joining node client: %s", refreshErr.Error()))
				}
			}
			tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Error reading cluster status (attempt %d/%d): %s", attempt, maxPollRetries, err.Error()))
			if attempt < maxPollRetries {
				time.Sleep(pollInterval)
				continue
			}
			resp.Diagnostics.AddError("Error polling cluster status after join", err.Error())
			return
		}

		statusCode := gjson.Get(statusResponse, "status.code").String()
		statusDesc := gjson.Get(statusResponse, "status.description").String()

		tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Node status: %s - %s (attempt %d/%d)", statusCode, statusDesc, attempt, maxPollRetries))

		switch {
		case statusCode == nodeStatusReady:
			tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Node ready after %d attempts (%.1f minutes)", attempt, float64(attempt)*pollInterval.Seconds()/60))
			finalStatusResponse = statusResponse

		case nodeIsJoining(statusCode):
			seenJoining = true

		case statusCode == nodeStatusDown || statusCode == nodeStatusKilled:
			if seenJoining {
				resp.Diagnostics.AddError(
					"Node join failed",
					fmt.Sprintf("Node entered status %q after starting join: %s", statusCode, statusDesc),
				)
				return
			}
			// Transient: node briefly restarts right after the async join request is accepted.
			tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Node status %q before join started (attempt %d/%d); treating as transient", statusCode, attempt, maxPollRetries))

		case statusCode == nodeStatusRemoving || statusCode == nodeStatusRemoved:
			resp.Diagnostics.AddError(
				"Node join failed",
				fmt.Sprintf("Node unexpectedly entered status %q during join: %s", statusCode, statusDesc),
			)
			return
		}

		if finalStatusResponse != "" {
			break
		}

		if attempt < maxPollRetries {
			time.Sleep(pollInterval)
		} else {
			resp.Diagnostics.AddError(
				"Timeout waiting for node to join cluster",
				fmt.Sprintf("Node did not reach ready state after %d attempts (120 minutes). Last status: %s - %s", maxPollRetries, statusCode, statusDesc),
			)
			return
		}
	}

	// Poll the cluster member until it reflects the joined node and status=r.
	// The semaphore is still held here, so no other node can start joining until
	// this loop exits. We always run this poll — even when we couldn't snapshot the
	// initial node count — to guarantee cluster stability before reporting success.
	{
		var expectedNodeCount int64 = -1
		if initialMemberNodeCount >= 0 {
			expectedNodeCount = initialMemberNodeCount + 1
			tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Waiting for member to report nodeCount=%d and status=r...", expectedNodeCount))
		} else {
			tflog.Info(ctx, "[resource_cm_cluster_node.go -> Create] Waiting for member to report status=r (initial node count unknown)...")
		}
		maxMemberRetries := 360 // up to 60 minutes
		memberPollInterval := 10 * time.Second
		memberReady := false
		for attempt := 1; attempt <= maxMemberRetries; attempt++ {
			memberStatus, memberErr := r.client.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO)
			if memberErr != nil {
				if strings.Contains(memberErr.Error(), "status: 401") {
					if refreshErr := r.client.RefreshToken(ctx, id); refreshErr == nil {
						tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Re-authenticated member client after token expiry (attempt %d/%d)", attempt, maxMemberRetries))
					}
				}
				tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Member poll error (attempt %d/%d): %s", attempt, maxMemberRetries, memberErr.Error()))
			} else {
				memberCount := gjson.Get(memberStatus, "nodeCount").Int()
				memberCode := gjson.Get(memberStatus, "status.code").String()
				tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Member: nodeCount=%d (want %d), status=%s (attempt %d/%d)", memberCount, expectedNodeCount, memberCode, attempt, maxMemberRetries))
				stable := memberCode == "r" && (expectedNodeCount < 0 || memberCount == expectedNodeCount)
				if stable {
					tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Create] Member stable after %d attempts", attempt))
					memberReady = true
					break
				}
			}
			if attempt < maxMemberRetries {
				time.Sleep(memberPollInterval)
			}
		}
		if !memberReady {
			resp.Diagnostics.AddError(
				"Cluster member did not stabilize after node join",
				fmt.Sprintf("Member did not reach ready state with updated node count after %d attempts (60 minutes). "+
					"The joining node reported ready but the cluster member has not yet converged. "+
					"Check cluster health before retrying.", maxMemberRetries),
			)
			return
		}
	}

	// Set plan values from final status
	plan.ID = types.StringValue(gjson.Get(finalStatusResponse, "nodeID").String())
	plan.NodeId = types.StringValue(gjson.Get(finalStatusResponse, "nodeID").String())
	plan.NodeCount = types.Int64Value(gjson.Get(finalStatusResponse, "nodeCount").Int())
	plan.StatusCode = types.StringValue(gjson.Get(finalStatusResponse, "status.code").String())
	plan.StatusDescription = types.StringValue(gjson.Get(finalStatusResponse, "status.description").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_cluster_node.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state by calling /v1/cluster on the joining node.
// This keeps node_id and other computed fields in sync after each apply.
func (r *resourceCMClusterNode) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMAddClusterNodeTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	joiningNodeHost, err := extractHost(state.Host.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid host for joining node", err.Error())
		return
	}
	nodeUsername := r.client.AuthData.Username
	nodePassword := r.client.AuthData.Password
	nodeDomain := r.client.AuthData.Domain
	nodeAuthDomain := r.client.AuthData.AuthDomain
	if state.Creds != nil {
		if !state.Creds.Username.IsNull() && !state.Creds.Username.IsUnknown() {
			nodeUsername = state.Creds.Username.ValueString()
		}
		if !state.Creds.Password.IsNull() && !state.Creds.Password.IsUnknown() {
			nodePassword = state.Creds.Password.ValueString()
		}
		if !state.Creds.Domain.IsNull() && !state.Creds.Domain.IsUnknown() {
			nodeDomain = state.Creds.Domain.ValueString()
		}
		if !state.Creds.AuthDomain.IsNull() && !state.Creds.AuthDomain.IsUnknown() {
			nodeAuthDomain = state.Creds.AuthDomain.ValueString()
		}
	}
	nodeConnAddr := joiningNodeHost
	if state.Creds != nil && !state.Creds.Address.IsNull() && !state.Creds.Address.IsUnknown() {
		if addr := state.Creds.Address.ValueString(); addr != "" {
			nodeConnAddr = addr
		}
	}
	nodeURL := nodeConnAddr
	if !strings.Contains(nodeURL, "://") {
		nodeURL = "https://" + nodeURL
	}
	// The node's auth service can be briefly unavailable after a cluster join even when status="r",
	// because auth restarts independently of Raft consensus readiness.
	const readMaxRetries = 180 // up to 30 minutes at 10s intervals
	const readRetryInterval = 10 * time.Second
	var (
		nodeClient *common.Client
		response   string
		lastErr    error
	)
	for attempt := 1; attempt <= readMaxRetries; attempt++ {
		nodeClient, lastErr = common.NewClient(ctx, id, &nodeURL, &nodeAuthDomain, &nodeDomain, &nodeUsername, &nodePassword, nil, common.TLSOptions{InsecureSkipVerify: true}, 180)
		if lastErr != nil {
			tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Read] attempt %d/%d: NewClient failed: %s", attempt, readMaxRetries, lastErr))
			if attempt < readMaxRetries {
				time.Sleep(readRetryInterval)
			}
			continue
		}
		response, lastErr = nodeClient.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO)
		if lastErr != nil {
			tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Read] attempt %d/%d: ReadDataByParam failed: %s", attempt, readMaxRetries, lastErr))
			if attempt < readMaxRetries {
				time.Sleep(readRetryInterval)
			}
			continue
		}
		if attempt > 1 {
			tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Read] succeeded on attempt %d/%d", attempt, readMaxRetries))
		}
		break
	}
	if lastErr != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+lastErr.Error()+" [resource_cm_cluster_node.go -> Read]["+id+"]")
		resp.Diagnostics.AddError("Error reading cluster info from joining node", lastErr.Error())
		return
	}

	nodeID := gjson.Get(response, "nodeID").String()
	state.ID = types.StringValue(nodeID)
	state.NodeId = types.StringValue(nodeID)
	state.NodeCount = types.Int64Value(gjson.Get(response, "nodeCount").Int())
	state.StatusCode = types.StringValue(gjson.Get(response, "status.code").String())
	state.StatusDescription = types.StringValue(gjson.Get(response, "status.description").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_cluster_node.go -> Read]["+id+"]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the node properties. Currently only public_address is updatable.
func (r *resourceCMClusterNode) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_cluster_node.go -> Update]["+id+"]")

	var plan, state CMAddClusterNodeTFSDK
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
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_cluster_node.go -> Update]["+id+"]")
			resp.Diagnostics.AddError("Invalid update payload", err.Error())
			return
		}

		// PATCH /v1/nodes/{id} - called on cluster member (provider's node), not on the node itself
		_, err = r.client.UpdateDataV2(ctx, nodeID, common.URL_NODES, payloadJSON)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_cluster_node.go -> Update]["+id+"]")
			resp.Diagnostics.AddError(
				"Error updating public_address",
				"Could not update public_address for node "+nodeID+": "+err.Error(),
			)
			return
		}

		tflog.Debug(ctx, "[resource_cm_cluster_node.go -> Update] Successfully updated public_address for node "+nodeID)
	}

	// Copy plan to state
	state.PublicAddress = plan.PublicAddress

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_cluster_node.go -> Update]["+id+"]")
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Delete removes the node from the cluster and clears the cluster config on the node itself.
func (r *resourceCMClusterNode) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	var state CMAddClusterNodeTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Serialize removals with additions: a concurrent add+remove causes the nodeCount
	// stability check to target the wrong count and can disrupt Raft consensus.
	nodeHost := state.Host.ValueString()
	tflog.Info(ctx, fmt.Sprintf("[%s] [resource_cm_cluster_node.go -> Delete] ATTEMPTING to acquire cluster join lock", nodeHost))
	clusterJoinMu.Lock()
	tflog.Info(ctx, fmt.Sprintf("[%s] [resource_cm_cluster_node.go -> Delete] LOCK ACQUIRED, proceeding with node removal", nodeHost))
	defer func() {
		clusterJoinMu.Unlock()
		tflog.Info(ctx, fmt.Sprintf("[%s] [resource_cm_cluster_node.go -> Delete] LOCK RELEASED", nodeHost))
	}()

	joiningNodeHost, err := extractHost(state.Host.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Invalid host for removed node", err.Error())
		return
	}
	nodeUsername := r.client.AuthData.Username
	nodePassword := r.client.AuthData.Password
	nodeDomain := r.client.AuthData.Domain
	nodeAuthDomain := r.client.AuthData.AuthDomain
	if state.Creds != nil {
		if !state.Creds.Username.IsNull() && !state.Creds.Username.IsUnknown() {
			nodeUsername = state.Creds.Username.ValueString()
		}
		if !state.Creds.Password.IsNull() && !state.Creds.Password.IsUnknown() {
			nodePassword = state.Creds.Password.ValueString()
		}
		if !state.Creds.Domain.IsNull() && !state.Creds.Domain.IsUnknown() {
			nodeDomain = state.Creds.Domain.ValueString()
		}
		if !state.Creds.AuthDomain.IsNull() && !state.Creds.AuthDomain.IsUnknown() {
			nodeAuthDomain = state.Creds.AuthDomain.ValueString()
		}
	}
	nodeConnAddr := joiningNodeHost
	if state.Creds != nil && !state.Creds.Address.IsNull() && !state.Creds.Address.IsUnknown() {
		if addr := state.Creds.Address.ValueString(); addr != "" {
			nodeConnAddr = addr
		}
	}
	nodeURL := nodeConnAddr
	if !strings.Contains(nodeURL, "://") {
		nodeURL = "https://" + nodeURL
	}
	nodeClient, err := common.NewClient(ctx, id, &nodeURL, &nodeAuthDomain, &nodeDomain, &nodeUsername, &nodePassword, nil, common.TLSOptions{InsecureSkipVerify: true}, 180)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_cluster_node.go -> Delete]["+id+"]")
		resp.Diagnostics.AddError("Unable to create HTTPS client for the removed node", err.Error())
		return
	}

	// Snapshot member's current node count before removal so we can verify it decrements.
	initialMemberNodeCount := int64(-1)
	if memberStatusBefore, memberErr := r.client.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO); memberErr == nil {
		initialMemberNodeCount = gjson.Get(memberStatusBefore, "nodeCount").Int()
		tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Delete] Member node count before removal: %d", initialMemberNodeCount))
	} else {
		tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Delete] Could not read member node count before removal (will poll for status=r only): %s", memberErr.Error()))
	}

	// Recover node ID from the joining node if missing from state (e.g. after a failed apply).
	nodeID := state.NodeId.ValueString()
	if nodeID == "" {
		response, err := nodeClient.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO)
		if err == nil {
			nodeID = gjson.Get(response, "nodeID").String()
		}
	}

	// Step 1: Remove the node from the cluster member list (called on the existing cluster member).
	// Skip if nodeID is still unknown — the node may never have fully joined.
	if nodeID != "" {
		endpoint := fmt.Sprintf("%s/%s", common.URL_NODES, nodeID)
		output, err := r.client.DeleteByURL(ctx, nodeID, endpoint)
		tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_cluster_node.go -> Delete]["+nodeID+"]["+output+"]")
		if err != nil {
			resp.Diagnostics.AddError(
				"Error removing node from cluster",
				"Could not remove node "+nodeID+" from cluster, unexpected error: "+err.Error(),
			)
			return
		}
	} else {
		tflog.Debug(ctx, "[resource_cm_cluster_node.go -> Delete]["+id+"] node ID unknown, skipping cluster member removal")
	}

	// Step 2: Delete the cluster configuration from the removed node itself.
	output, err := nodeClient.DeleteByURL(ctx, id, common.URL_CLUSTER_INFO)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_cluster_node.go -> Delete]["+id+"]["+output+"]")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_cluster_node.go -> Delete]["+id+"]")
		resp.Diagnostics.AddError(
			"Error deleting cluster config from removed node",
			"Node was removed from the cluster but its local cluster config could not be cleared: "+err.Error(),
		)
		return
	}

	// Step 3: Poll the cluster member until it reflects the removal (nodeCount decremented, status=r).
	// The semaphore is still held here — the next join or removal cannot start until the cluster
	// has fully settled, preventing a concurrent Create from snapshotting a stale node count.
	{
		var expectedNodeCount int64 = -1
		if initialMemberNodeCount >= 0 {
			expectedNodeCount = initialMemberNodeCount - 1
			tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Delete] Waiting for member to report nodeCount=%d and status=r...", expectedNodeCount))
		} else {
			tflog.Info(ctx, "[resource_cm_cluster_node.go -> Delete] Waiting for member to report status=r (initial node count unknown)...")
		}
		maxMemberRetries := 360 // up to 60 minutes
		memberPollInterval := 10 * time.Second
		memberReady := false
		for attempt := 1; attempt <= maxMemberRetries; attempt++ {
			memberStatus, memberErr := r.client.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO)
			if memberErr != nil {
				if strings.Contains(memberErr.Error(), "status: 401") {
					if refreshErr := r.client.RefreshToken(ctx, id); refreshErr == nil {
						tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Delete] Re-authenticated member client after token expiry (attempt %d/%d)", attempt, maxMemberRetries))
					}
				}
				tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Delete] Member poll error (attempt %d/%d): %s", attempt, maxMemberRetries, memberErr.Error()))
			} else {
				memberCount := gjson.Get(memberStatus, "nodeCount").Int()
				memberCode := gjson.Get(memberStatus, "status.code").String()
				tflog.Debug(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Delete] Member: nodeCount=%d (want %d), status=%s (attempt %d/%d)", memberCount, expectedNodeCount, memberCode, attempt, maxMemberRetries))
				stable := memberCode == "r" && (expectedNodeCount < 0 || memberCount == expectedNodeCount)
				if stable {
					tflog.Info(ctx, fmt.Sprintf("[resource_cm_cluster_node.go -> Delete] Member stable after removal, attempt %d", attempt))
					memberReady = true
					break
				}
			}
			if attempt < maxMemberRetries {
				time.Sleep(memberPollInterval)
			}
		}
		if !memberReady {
			resp.Diagnostics.AddError(
				"Cluster member did not stabilize after node removal",
				fmt.Sprintf("Member did not reach ready state with updated node count after %d attempts (60 minutes). "+
					"The node was removed but the cluster may still be converging. "+
					"Check cluster health before retrying.", maxMemberRetries),
			)
		}
	}
}

func (r *resourceCMClusterNode) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	r.client = client
}
