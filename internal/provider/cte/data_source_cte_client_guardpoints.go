package cte

import (
	"context"
	"encoding/json"
	"fmt"
	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceCTEClientGuardPoint{}
	_ datasource.DataSourceWithConfigure = &dataSourceCTEClientGuardPoint{}
)

func NewDataSourceCTEClientGuardPoint() datasource.DataSource {
	return &dataSourceCTEClientGuardPoint{}
}

type dataSourceCTEClientGuardPoint struct {
	client *common.Client
}

type CTEClientGuardPointDataSourceModel struct {
	ClientName       types.String                   `tfsdk:"client_name"`
	Limit            types.Int64                    `tfsdk:"limit"`
	Skip             types.Int64                    `tfsdk:"skip"`
	ClientGuardPoint []CTEClientGuardPointListTFSDK `tfsdk:"client_guardpoint"`
}

func (d *dataSourceCTEClientGuardPoint) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client_guardpoint"
}

func (d *dataSourceCTEClientGuardPoint) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"client_name": schema.StringAttribute{
				Description: "Name of the CTE client whose GuardPoints are to be listed.",
				Required:    true,
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of client guardpoints to return. If unset, all guardpoints are returned (a warning is emitted if the result set is large).",
			},
			"skip": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of client guardpoints to skip before returning results, for pagination. Defaults to 0.",
			},
			"client_guardpoint": schema.ListNestedAttribute{
				Description: "List of GuardPoints configured on the client.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The unique identifier of the GuardPoint.",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "URI of the GuardPoint.",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "Account of the GuardPoint.",
							Computed:    true,
						},
						"application": schema.StringAttribute{
							Description: "Application associated with the GuardPoint.",
							Computed:    true,
						},
						"dev_account": schema.StringAttribute{
							Description: "Dev account of the GuardPoint.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Date and time the GuardPoint was created.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Date and time the GuardPoint was last updated.",
							Computed:    true,
						},
						"client_id": schema.StringAttribute{
							Description: "ID of the client the GuardPoint is applied to.",
							Computed:    true,
						},
						"client_group_id": schema.StringAttribute{
							Description: "ID of the client group the GuardPoint is applied to, if applicable.",
							Computed:    true,
						},
						"client_group_name": schema.StringAttribute{
							Description: "Name of the client group the GuardPoint is applied to, if applicable.",
							Computed:    true,
						},
						"client_name": schema.StringAttribute{
							Description: "Name of the client the GuardPoint is applied to.",
							Computed:    true,
						},
						"guard_point_type": schema.StringAttribute{
							Description: "Type of the GuardPoint, e.g. directory_auto, directory_manual, rawdevice_manual, rawdevice_auto, cloudstorage_auto, cloudstorage_manual or ransomware_protection.",
							Computed:    true,
						},
						"guard_enabled": schema.BoolAttribute{
							Description: "Whether the GuardPoint is enabled.",
							Computed:    true,
						},
						"automount_enabled": schema.BoolAttribute{
							Description: "Whether automount is enabled for the GuardPoint.",
							Computed:    true,
						},
						"guard_path": schema.StringAttribute{
							Description: "Path of the GuardPoint.",
							Computed:    true,
						},
						"policy_id": schema.StringAttribute{
							Description: "ID of the CTE policy applied to the GuardPoint.",
							Computed:    true,
						},
						"pending_operation": schema.StringAttribute{
							Description: "Pending operation on the GuardPoint, if any.",
							Computed:    true,
						},
						"disk_name": schema.StringAttribute{
							Description: "Name of the disk associated with the GuardPoint (raw partition GuardPoints).",
							Computed:    true,
						},
						"diskgroup_name": schema.StringAttribute{
							Description: "Name of the disk group associated with the GuardPoint (raw partition GuardPoints).",
							Computed:    true,
						},
						"preserve_sparse_regions": schema.BoolAttribute{
							Description: "Whether to preserve sparse file regions. Only applicable for raw partition GuardPoints.",
							Computed:    true,
						},
						"docker_img_id": schema.StringAttribute{
							Description: "ID of the docker image the GuardPoint is applied to, if applicable.",
							Computed:    true,
						},
						"docker_cont_id": schema.StringAttribute{
							Description: "ID of the docker container the GuardPoint is applied to, if applicable.",
							Computed:    true,
						},
						"early_access": schema.BoolAttribute{
							Description: "Whether secure start (early access) is enabled for the GuardPoint.",
							Computed:    true,
						},
						"type": schema.StringAttribute{
							Description: "Type of the resource the GuardPoint is applied to.",
							Computed:    true,
						},
						"policy_name": schema.StringAttribute{
							Description: "Name of the CTE policy applied to the GuardPoint.",
							Computed:    true,
						},
						"network_share_credentials_id": schema.StringAttribute{
							Description: "ID of the network share credentials associated with the GuardPoint, if applicable.",
							Computed:    true,
						},
						"disabled_reason": schema.StringAttribute{
							Description: "Reason the GuardPoint is disabled, if applicable.",
							Computed:    true,
						},
						"guard_point_state": schema.StringAttribute{
							Description: "State of the GuardPoint.",
							Computed:    true,
						},
						"attr": schema.MapAttribute{
							Description: "Additional attributes of the GuardPoint.",
							Computed:    true,
							ElementType: types.StringType,
						},
						"is_idt_capable_device": schema.BoolAttribute{
							Description: "Whether the device is IDT (Information Dispersal Technology) capable.",
							Computed:    true,
						},
						"cifs_enabled": schema.BoolAttribute{
							Description: "Whether CIFS is enabled for the GuardPoint.",
							Computed:    true,
						},
						"is_esg_capable_device": schema.BoolAttribute{
							Description: "Whether the device is ESG (Efficient Storage GuardPoint) capable.",
							Computed:    true,
						},
						"metadata": schema.StringAttribute{
							Description: "Metadata associated with the GuardPoint.",
							Computed:    true,
						},
						"csi_guard_status": schema.StringAttribute{
							Description: "CSI guard status of the GuardPoint (Kubernetes CSI GuardPoints).",
							Computed:    true,
						},
						"mfa_enabled": schema.BoolAttribute{
							Description: "Whether MFA (Multi-Factor Authentication) is enabled for the GuardPoint.",
							Computed:    true,
						},
						"native_domain": schema.StringAttribute{
							Description: "Native domain of the GuardPoint.",
							Computed:    true,
						},
						"gp_network_path": schema.StringAttribute{
							Description: "Network path of the GuardPoint (network share GuardPoints).",
							Computed:    true,
						},
						"dps_name": schema.StringAttribute{
							Description: "Name of the designated primary set associated with the GuardPoint, if applicable.",
							Computed:    true,
						},
						"dps_id": schema.StringAttribute{
							Description: "ID of the designated primary set associated with the GuardPoint, if applicable.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceCTEClientGuardPoint) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cteclientguardpoint.go -> Read][" + id + "]")
	var state CTEClientGuardPointDataSourceModel
	req.Config.Get(ctx, &state)
	limitVal, skipVal := resolvePagedListParams(state.Limit, state.Skip)
	jsonStr, total, err := d.client.GetAllPagedWithLimit(ctx, id, common.URL_CTE_CLIENT+"/"+state.ClientName.ValueString()+"/guardpoints", skipVal, limitVal)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cteclientguardpoint.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}
	warnIfPagedResultLarge(&resp.Diagnostics, "CTE client guardpoints", total, limitVal)
	client_guardpoints := []CTEClientGuardPointListJSON{}
	err = json.Unmarshal([]byte(jsonStr), &client_guardpoints)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cteclientguardpoint.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read CTE Policy from CM",
			err.Error(),
		)
		return
	}
	for _, guardpoint := range client_guardpoints {
		client_guardpoint := CTEClientGuardPointListTFSDK{}
		client_guardpoint.ID = types.StringValue(guardpoint.ID)
		client_guardpoint.URI = types.StringValue(guardpoint.URI)
		client_guardpoint.Account = types.StringValue(guardpoint.Account)
		client_guardpoint.Application = types.StringValue(guardpoint.Application)
		client_guardpoint.DevAccount = types.StringValue(guardpoint.DevAccount)
		client_guardpoint.CreatedAt = types.StringValue(guardpoint.CreatedAt)
		client_guardpoint.UpdatedAt = types.StringValue(guardpoint.UpdatedAt)
		client_guardpoint.ClientID = types.StringValue(guardpoint.ClientID)
		client_guardpoint.ClientGroupID = types.StringValue(guardpoint.ClientGroupID)
		client_guardpoint.ClientGroupName = types.StringValue(guardpoint.ClientGroupName)
		client_guardpoint.ClientName = types.StringValue(guardpoint.ClientName)
		client_guardpoint.GuardPointType = types.StringValue(guardpoint.GuardPointType)
		client_guardpoint.GuardEnabled = types.BoolValue(guardpoint.GuardEnabled)
		client_guardpoint.IsAutomountEnabled = types.BoolValue(guardpoint.IsAutomountEnabled)
		client_guardpoint.GuardPath = types.StringValue(guardpoint.GuardPath)
		client_guardpoint.PolicyID = types.StringValue(guardpoint.PolicyID)
		client_guardpoint.PendingOperation = types.StringValue(guardpoint.PendingOperation)
		client_guardpoint.DiskName = types.StringValue(guardpoint.DiskName)
		client_guardpoint.DiskgroupName = types.StringValue(guardpoint.DiskgroupName)
		client_guardpoint.PreserveSparseRegions = types.BoolValue(guardpoint.PreserveSparseRegions)
		client_guardpoint.DockerImgID = types.StringValue(guardpoint.DockerImgID)
		client_guardpoint.DockerContID = types.StringValue(guardpoint.DockerContID)
		client_guardpoint.EarlyAccess = types.BoolValue(guardpoint.EarlyAccess)
		client_guardpoint.Type = types.StringValue(guardpoint.Type)
		client_guardpoint.PolicyName = types.StringValue(guardpoint.PolicyName)
		client_guardpoint.NetworkShareCredentialsID = types.StringValue(guardpoint.NetworkShareCredentialsID)
		client_guardpoint.DisabledReason = types.StringValue(guardpoint.DisabledReason)
		client_guardpoint.GuardPointState = types.StringValue(guardpoint.GuardPointState)
		client_guardpoint.IsDeviceIDTCapable = types.BoolValue(guardpoint.IsDeviceIDTCapable)
		client_guardpoint.IsCIFSEnabled = types.BoolValue(guardpoint.IsCIFSEnabled)
		client_guardpoint.IsDeviceESGCapable = types.BoolValue(guardpoint.IsDeviceESGCapable)
		client_guardpoint.Metadata = types.StringValue(guardpoint.Metadata)
		client_guardpoint.CSIGuardStatus = types.StringValue(guardpoint.CSIGuardStatus)
		client_guardpoint.MFAEnabled = types.BoolValue(guardpoint.MFAEnabled)
		client_guardpoint.NativeDomain = types.StringValue(guardpoint.NativeDomain)
		client_guardpoint.GPNetworkPath = types.StringValue(guardpoint.GPNetworkPath)
		client_guardpoint.DpsName = types.StringValue(guardpoint.DpsName)
		client_guardpoint.DpsID = types.StringValue(guardpoint.DpsID)

		AttrMap := make(map[string]attr.Value)
		for k, v := range guardpoint.Attr {
			AttrMap[k] = types.StringValue(fmt.Sprintf("%v", v))
		}

		Attr, diags := types.MapValue(types.StringType, AttrMap)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		client_guardpoint.Attr = Attr
		state.ClientGuardPoint = append(state.ClientGuardPoint, client_guardpoint)
	}
	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cteclientguardpoint.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceCTEClientGuardPoint) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}
