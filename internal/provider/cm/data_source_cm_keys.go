package cm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceKeys{}
	_ datasource.DataSourceWithConfigure = &dataSourceKeys{}
)

func NewDataSourceKeys() datasource.DataSource {
	return &dataSourceKeys{}
}

type dataSourceKeys struct {
	client *common.Client
}

type keysDataSourceModel struct {
	Keys []CMKeysListTFSDK `tfsdk:"keys"`
}

func (d *dataSourceKeys) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_keys_list"
}

func (d *dataSourceKeys) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"keys": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"uri": schema.StringAttribute{
							Computed: true,
						},
						"account": schema.StringAttribute{
							Computed: true,
						},
						"application": schema.StringAttribute{
							Computed: true,
						},
						"dev_account": schema.StringAttribute{
							Computed: true,
						},
						"created_at": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"updated_at": schema.StringAttribute{
							Computed: true,
						},
						"usage_mask": schema.Int64Attribute{
							Computed: true,
						},
						"version": schema.Int64Attribute{
							Computed: true,
						},
						"algorithm": schema.StringAttribute{
							Computed: true,
						},
						"size": schema.Int64Attribute{
							Computed: true,
						},
						"format": schema.StringAttribute{
							Computed: true,
						},
						"unexportable": schema.BoolAttribute{
							Computed: true,
						},
						"undeletable": schema.BoolAttribute{
							Computed: true,
						},
						"object_type": schema.StringAttribute{
							Computed: true,
						},
						"activation_date": schema.StringAttribute{
							Computed: true,
						},
						"deactivation_date": schema.StringAttribute{
							Computed: true,
						},
						"archive_date": schema.StringAttribute{
							Computed: true,
						},
						"destroy_date": schema.StringAttribute{
							Computed: true,
						},
						"revocation_reason": schema.StringAttribute{
							Computed: true,
						},
						"state": schema.StringAttribute{
							Computed: true,
						},
						"uuid": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceKeys) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_users.go -> Read]["+id+"]")
	var state keysDataSourceModel

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_KEY_MANAGEMENT)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_keys.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read Keys from CM",
			err.Error(),
		)
		return
	}

	var data []map[string]any

	err = json.Unmarshal([]byte(jsonStr), &data)

	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_keys.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read keys from CM",
			err.Error(),
		)
		return
	}

	for _, key := range data {
		keyState := CMKeysListTFSDK{}
		if key["id"] != nil {
			keyState.ID = types.StringValue(key["id"].(string))
		}
		if key["uri"] != nil {
			keyState.URI = types.StringValue(key["uri"].(string))
		}
		if key["account"] != nil {
			keyState.Account = types.StringValue(key["account"].(string))
		}
		if key["application"] != nil {
			keyState.Application = types.StringValue(key["application"].(string))
		}
		if key["devAccount"] != nil {
			keyState.DevAccount = types.StringValue(key["devAccount"].(string))
		}
		if key["createdAt"] != nil {
			keyState.CreatedAt = types.StringValue(key["createdAt"].(string))
		}
		if key["name"] != nil {
			keyState.Name = types.StringValue(key["name"].(string))
		}
		if key["updatedAt"] != nil {
			keyState.UpdatedAt = types.StringValue(key["updatedAt"].(string))
		}
		if key["usageMask"] != nil {
			keyState.UsageMask = types.Int64Value(int64(key["usageMask"].(float64)))
		}
		if key["version"] != nil {
			keyState.Version = types.Int64Value(int64(key["version"].(float64)))
		}
		if key["algorithm"] != nil {
			keyState.Algorithm = types.StringValue(key["algorithm"].(string))
		}
		if key["size"] != nil {
			keyState.Size = types.Int64Value(int64(key["size"].(float64)))
		}
		if key["format"] != nil {
			keyState.Format = types.StringValue(key["format"].(string))
		}
		if key["unexportable"] != nil {
			keyState.Unexportable = types.BoolValue(bool(key["unexportable"].(bool)))
		}
		if key["undeletable"] != nil {
			keyState.Undeletable = types.BoolValue(bool(key["undeletable"].(bool)))
		}
		if key["objectType"] != nil {
			keyState.ObjectType = types.StringValue(key["objectType"].(string))
		}
		if key["activationDate"] != nil {
			keyState.ActivationDate = types.StringValue(key["activationDate"].(string))
		}
		if key["deactivationDate"] != nil {
			keyState.DeactivationDate = types.StringValue(key["deactivationDate"].(string))
		}
		if key["archiveDate"] != nil {
			keyState.ArchiveDate = types.StringValue(key["archiveDate"].(string))
		}
		if key["destroyDate"] != nil {
			keyState.DestroyDate = types.StringValue(key["destroyDate"].(string))
		}
		if key["revocationReason"] != nil {
			keyState.RevocationReason = types.StringValue(key["revocationReason"].(string))
		}
		if key["state"] != nil {
			keyState.State = types.StringValue(key["state"].(string))
		}
		if key["uuid"] != nil {
			keyState.UUID = types.StringValue(key["uuid"].(string))
		}
		if key["description"] != nil {
			keyState.Description = types.StringValue(key["description"].(string))
		}
		state.Keys = append(state.Keys, keyState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_keys.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceKeys) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
