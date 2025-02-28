package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCMCluster{}
	_ resource.ResourceWithConfigure = &resourceCMCluster{}
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

// Schema defines the schema for the resource.
func (r *resourceCMCluster) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"nodes": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"host": schema.StringAttribute{
							Required:    true,
							Description: "The hostname or IP of the node",
						},
						"original": schema.BoolAttribute{
							Optional:    true,
							Description: "This node is the same server as the provider is configured to use. It is used as the first node in the cluster. All other nodes will have the same state as this node.",
						},
						"port": schema.Int64Attribute{
							Required:    true,
							Description: "The port of the node, typically 5432",
						},
						"public_address": schema.StringAttribute{
							Required:    true,
							Description: "The fully qualified domain name (FQDN) or public IP of this node. This attribute is used by CipherTrust Manager connectors to learn how to access this particular node of the cluster remotely.",
						},
						"credentials": schema.SingleNestedAttribute{
							Optional:    true,
							Description: "Credentials for the node that want to join the cluster. This is optional and if not provided, provider's config node credentials shall be tried.",
							Attributes: map[string]schema.Attribute{
								"username": schema.StringAttribute{
									Optional:    true,
									Description: "Username for the node",
								},
								"password": schema.StringAttribute{
									Optional:    true,
									Description: "Password for the node",
								},
								"domain": schema.StringAttribute{
									Optional:    true,
									Description: "CipherTrust domain to log in to. Default is the empty string (root domain).",
								},
								"auth_domain": schema.StringAttribute{
									Optional:    true,
									Description: "CipherTrust authentication domain of the user. This is the domain where the user was created.",
								},
								"no_ssl_verify": &schema.BoolAttribute{
									Optional:    true,
									Description: "Set to false to verify the server's certificate chain and host name.",
								},
							},
						},
					},
				},
			},
			"node_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of nodes in the cluster",
			},
			"node_id": schema.StringAttribute{
				Computed:    true,
				Description: "This CipherTrust manager node ID",
			},
			"status_code": schema.StringAttribute{
				Computed:    true,
				Description: "short code for cluster status: r == ready",
			},
			"status_description": schema.StringAttribute{
				Computed:    true,
				Description: "cluster status",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMCluster) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cluster.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMClusterTFSDK
	regexURL := regexp.MustCompile(`https://([a-zA-Z0-9.\-]+)`)

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	for _, node := range plan.Nodes {
		if node.Original.ValueBool() {
			//Let's check if the cluster already exists for the primary node
			response, err := r.client.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Error reading existing cluster information from CipherTrust Manager: ",
					"Could not read cluster information, unexpected error: "+err.Error(),
				)
				return
			}
			statusCode := gjson.Get(response, "status.code").String()
			if statusCode == "none" {
				//This means we need to create a new cluster with the primary node
				var newClusterPayload NewCMClusterNodeJSON
				if node.Host.ValueString() != "" && node.Host.ValueString() != types.StringNull().ValueString() {
					url := regexURL.FindStringSubmatch(node.Host.ValueString())
					newClusterPayload.LocalNodeHost = url[1]
				}
				if node.Port.ValueInt64() != types.Int64Null().ValueInt64() {
					newClusterPayload.LocalNodePort = node.Port.ValueInt64()
				}
				if node.PublicAddress.ValueString() != "" && node.PublicAddress.ValueString() != types.StringNull().ValueString() {
					url := regexURL.FindStringSubmatch(node.PublicAddress.ValueString())
					newClusterPayload.PublicAddress = url[1]
				}

				payloadJSON, err := json.Marshal(newClusterPayload)
				if err != nil {
					tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
					resp.Diagnostics.AddError(
						"Invalid payload: Create New Cluster",
						err.Error(),
					)
					return
				}

				response, err := r.client.PostDataV2(ctx, id, common.URL_NEW_CLUSTER, payloadJSON)
				if err != nil {
					tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
					resp.Diagnostics.AddError(
						"Error creating new cluster on CipherTrust Manager: ",
						"Could not create new cluster, unexpected error: "+err.Error(),
					)
					return
				}
				plan.NodeCount = types.Int64Value(gjson.Get(response, "nodeCount").Int())
				plan.NodeId = types.StringValue(gjson.Get(response, "nodeID").String())
				plan.StatusCode = types.StringValue(gjson.Get(response, "status.code").String())
				plan.StatusDescription = types.StringValue(gjson.Get(response, "status.description").String())
			}
		} else {
			//Let's join remaining nodes to the cluster
			//Steps are -
			//1. Create CSR on the node that wants to join the cluster
			//For this step we need to create a client object for the joining node
			node_address := node.Host.ValueString()
			node_username := node.Creds.Username.ValueString()
			node_password := node.Creds.Password.ValueString()
			node_domain := node.Creds.Domain.ValueString()
			node_auth_domain := node.Creds.AuthDomain.ValueString()
			node_client, err := common.NewClient(ctx, id, &node_address, &node_auth_domain, &node_domain, &node_username, &node_password, true, 180)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Unable to create the HTTPS client for the joining node.",
					err.Error(),
				)
				return
			}

			var payloadCSR NewCSRJSON

			urlLocalNode := regexURL.FindStringSubmatch(node.Host.ValueString())
			payloadCSR.LocalNodeHost = urlLocalNode[1]

			urlLocalNodePubAddress := regexURL.FindStringSubmatch(r.client.CipherTrustURL)
			payloadCSR.PublicAddress = urlLocalNodePubAddress[1]

			payloadCSRJSON, err := json.Marshal(payloadCSR)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Invalid payload: Create CSR",
					err.Error(),
				)
				return
			}
			responseCSR, err := node_client.PostDataV2(ctx, id, common.URL_CREATE_CSR, payloadCSRJSON)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Error creating new CSR on the joining node: ", err.Error(),
				)
				return
			}

			//2. Sign the CSR from an existing node in the cluster
			var payloadSignCSR SignRequestJSON
			payloadSignCSR.CSR = gjson.Get(responseCSR, "csr").String()

			urlNewNode := regexURL.FindStringSubmatch(node.Host.ValueString())
			payloadSignCSR.NewNodeHost = urlNewNode[1]

			urlNewNodePub := regexURL.FindStringSubmatch(r.client.CipherTrustURL)
			payloadSignCSR.PublicAddress = urlNewNodePub[1]

			payloadSignCSR.SharedHSMPartition = false
			payloadSignCSRJSON, err := json.Marshal(payloadSignCSR)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Invalid payload: Sign CSR",
					err.Error(),
				)
				return
			}
			responseSignCSR, err := r.client.PostDataV2(ctx, id, common.URL_SIGN_CERT, payloadSignCSRJSON)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Error signing CSR on the existing node: ", err.Error(),
				)
				return
			}

			//3. Now send the request to join the cluster with the returned certificate and CA chain
			var payloadJoinNode JoinClusterJSON
			payloadJoinNode.CAChain = gjson.Get(responseSignCSR, "cachain").String()
			payloadJoinNode.Cert = gjson.Get(responseSignCSR, "cert").String()
			payloadJoinNode.MKEKBlob = gjson.Get(responseSignCSR, "mkek_blob").String()
			urlJoinNode := regexURL.FindStringSubmatch(node.Host.ValueString())
			urlMemberNodePub := regexURL.FindStringSubmatch(r.client.CipherTrustURL)
			payloadJoinNode.LocalNodeHost = urlJoinNode[1]
			payloadJoinNode.MemberNodeHost = urlMemberNodePub[1]

			if node.Port.ValueInt64() != types.Int64Null().ValueInt64() {
				payloadJoinNode.LocalNodePort = node.Port.ValueInt64()
			}
			payloadJoinNodeJSON, err := json.Marshal(payloadJoinNode)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Invalid payload: Join Node",
					err.Error(),
				)
				return
			}
			//responseJoinNode, err := r.client.PostDataV2(ctx, id, common.URL_CLUSTER_JOIN, payloadJoinNodeJSON)
			responseJoinNode, err := node_client.PostDataV2(ctx, id, common.URL_CLUSTER_JOIN, payloadJoinNodeJSON)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Error signing CSR on the existing node: ", err.Error(),
				)
				return
			}
			plan.NodeCount = types.Int64Value(gjson.Get(responseJoinNode, "nodeCount").Int())
			plan.ID = types.StringValue(gjson.Get(responseJoinNode, "nodeID").String())
			plan.NodeId = types.StringValue(gjson.Get(responseJoinNode, "nodeID").String())
			plan.StatusCode = types.StringValue(gjson.Get(responseJoinNode, "status.code").String())
			plan.StatusDescription = types.StringValue(gjson.Get(responseJoinNode, "status.description").String())
		}
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cluster.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMCluster) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMClusterTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, "all", common.URL_CLUSTER_INFO)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cluster.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading cluster info on CipherTrust Manager: ",
			"Could not cluster info : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.NodeCount = types.Int64Value(gjson.Get(response, "nodeCount").Int())
	state.ID = types.StringValue(gjson.Get(response, "nodeID").String())
	state.NodeId = types.StringValue(gjson.Get(response, "nodeID").String())
	state.StatusCode = types.StringValue(gjson.Get(response, "status.code").String())
	state.StatusDescription = types.StringValue(gjson.Get(response, "status.description").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cluster.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMCluster) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMCluster) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMClusterTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing license
	url := fmt.Sprintf("%s/%s", r.client.CipherTrustURL, common.URL_CLUSTER_INFO)
	output, err := r.client.DeleteByURL(ctx, state.NodeId.ValueString(), url)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cluster.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting cluster",
			"Could not cluster, unexpected error: "+err.Error(),
		)
		return
	}
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
