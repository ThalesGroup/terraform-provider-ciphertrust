package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceOCIVault{}
	_ datasource.DataSourceWithConfigure = &dataSourceOCIVault{}
)

func NewDataSourceOCIVault() datasource.DataSource {
	return &dataSourceOCIVault{}
}

type dataSourceOCIVault struct {
	client *common.Client
}

type OCIVaultDataSourceModel struct {
	Filters types.Map    `tfsdk:"filters"`
	Matched types.Int64  `tfsdk:"matched"`
	Vaults  []VaultTFSDK `tfsdk:"vaults"`
}

func (d *dataSourceOCIVault) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_vault_list"
}

func (d *dataSourceOCIVault) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *dataSourceOCIVault) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of CipherTrust Manager vaults.\n\n" +
			"Give a filter of 'limit=-1' to list more than 10 matches.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A list of key:value pairs where the 'key' is any of the filters available in CipherTrust Manager's API playground for listing CipherTrust Manager OCI vaults.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The number of vaults which matched the filters.",
			},
			"vaults": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's CipherTrust Manager resource ID.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager's unique identifier for the resource.",
						},
						"account": schema.StringAttribute{
							Computed:    true,
							Description: "The account which owns this resource.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the application was created",
						},
						"refreshed_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the application was refreshed.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the application was updated.",
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager cloud name.",
						},
						"connection_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager OCI connection ID or connection name.",
						},
						"region": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's region.",
						},
						"tenancy": schema.StringAttribute{
							Computed:    true,
							Description: "The tenancy name.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's name.",
						},
						"acls": schema.SetNestedAttribute{
							Computed:    true,
							Description: "List of ACLs that have been added to the vault.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"user_id": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager user ID.",
									},
									"group": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager group name.",
									},
									"actions": schema.SetAttribute{
										Computed:    true,
										Description: "Permitted actions.",
										ElementType: types.StringType,
									},
								},
							},
						},
						"compartment_id": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's OCID.",
						},
						"compartment_name": schema.StringAttribute{
							Computed:    true,
							Description: "Compartment name.",
						},
						"lifecycle_state": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's current lifecycle state.",
						},
						"management_endpoint": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's management endpoint.",
						},
						"vault_type": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's type.",
						},
						"wrappingkey_id": schema.StringAttribute{
							Computed:    true,
							Description: "Vault's wrapping key OCID.",
						},
						"time_created": schema.StringAttribute{
							Computed:    true,
							Description: "The time the vault was created.",
						},
						"freeform_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "The freeform tags of the vault.",
						},
						"defined_tags": schema.SetNestedAttribute{
							Computed:    true,
							Description: "The defined tags of the vault.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"tag": schema.StringAttribute{
										Computed: true,
									},
									"values": schema.MapAttribute{
										Computed:    true,
										ElementType: types.StringType,
									},
								},
							},
						},
						"restored_from_vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "OCID of the vault this vault was restored from.",
						},
						"replication_id": schema.StringAttribute{
							Computed:    true,
							Description: "The replication ID associated with a vault operation.",
						},
						"is_primary": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the key belongs to a primary vault or a replica vault.",
						},
						"vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's OCID.",
						},
						"bucket_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the OCI bucket.",
						},
						"bucket_namespace": schema.StringAttribute{
							Computed:    true,
							Description: "Namespace of the OCI bucket.",
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceOCIVault) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_oci_vaults.go -> Read]["+id+"]")
	var state OCIVaultDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		val, ok := v.(types.String)
		if ok {
			filters.Add(k, val.ValueString())
		}
	}
	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_OCI+"/vaults/", filters)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_vaults.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read OCI vault from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var vaults DataSourceVaultsJSON
	err = json.Unmarshal([]byte(jsonStr), &vaults)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_vaults.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read OCI vault from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	for ndx, vault := range vaults.Resources {
		vaultTFSDK := VaultTFSDK{
			VaultCommonTFSDK: VaultCommonTFSDK{
				ID:                  types.StringValue(vault.ID),
				URI:                 types.StringValue(vault.URI),
				Account:             types.StringValue(vault.Account),
				CreatedAt:           types.StringValue(vault.CreatedAt),
				UpdatedAt:           types.StringValue(vault.UpdatedAt),
				CompartmentID:       types.StringValue(vault.CompartmentID),
				DisplayName:         types.StringValue(vault.DisplayName),
				VaultID:             types.StringValue(vault.VaultID),
				LifecycleState:      types.StringValue(vault.LifecycleState),
				ManagementEndpoint:  types.StringValue(vault.ManagementEndpoint),
				TimeCreated:         types.StringValue(vault.TimeCreated),
				CloudName:           types.StringValue(vault.CloudName),
				Connection:          types.StringValue(vault.Connection),
				VaultType:           types.StringValue(vault.VaultType),
				WrappingkeyID:       types.StringValue(vault.WrappingkeyID),
				RestoredFromVaultID: types.StringValue(vault.RestoredFromVaultID),
				ReplicationID:       types.StringValue(vault.ReplicationID),
				IsPrimary:           types.BoolValue(vault.IsPrimary),
				RefreshedAt:         types.StringValue(vault.RefreshedAt),
				Tenancy:             types.StringValue(vault.Tenancy),
				Region:              types.StringValue(vault.Region),
				CompartmentName:     types.StringValue(vault.CompartmentName),
			},
		}
		bucketName := ""
		if vault.BucketName != nil {
			bucketName = *vault.BucketName
		}
		bucketNamespace := ""
		if vault.BucketNamespace != nil {
			bucketNamespace = *vault.BucketNamespace
		}
		resourceJSON := gjson.Get(jsonStr, "resources").Array()[ndx].String()
		vaultTFSDK.BucketParamsTFSDK = BucketParamsTFSDK{
			BucketName:      types.StringValue(bucketName),
			BucketNamespace: types.StringValue(bucketNamespace),
		}
		acls.SetAclsStateFromJSON(ctx, gjson.Get(resourceJSON, "acls"), &vaultTFSDK.Acls, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setFreeformTagsState(ctx, vault.FreeformTags, &vaultTFSDK.FreeformTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setDefinedTagsState(ctx, vault.DefinedTags, &vaultTFSDK.DefinedTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Vaults = append(state.Vaults, vaultTFSDK)
	}
	state.Matched = types.Int64Value(gjson.Get(jsonStr, "total").Int())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_oci_vaults.go -> Read]["+id+"]")
}
