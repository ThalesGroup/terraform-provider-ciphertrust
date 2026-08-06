package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

// awsKeyRotationFiltersTable documents the supported query parameters for the filters map.
// All values are supplied as strings in the Terraform filters map regardless of the
// underlying API type shown below.
const awsKeyRotationFiltersTable = "\n\n> **Note:** Although some filters represent integers, all filter values must be specified as strings. " +
	"For example, use `\"-1\"` rather than `-1`.\n\n" +
	"| filter               | type    | description |\n" +
	"|----------------------|---------|-------------|\n" +
	"| skip                 | integer | Index of the first result to return (default: 0). |\n" +
	"| limit                | integer | Max number of results to return (default: 10). Use `\"-1\"` to return all matches. |\n" +
	"| sort                 | string  | Fields to sort by. Valid sort fields are `updatedAt`, `createdAt`, `RotationDate`, and `ValidTo`. Prefix with `-` for descending order (for example, `-createdAt`). |\n" +
	"| key_source           | string  | Filter by key source. |\n" +
	"| key_material_origin  | string  | Filter by key material origin. |\n" +
	"| ImportState          | string  | Filter by ImportState. |\n" +
	"| KeyMaterialState     | string  | Filter by key material state. |\n" +
	"| RotationType         | string  | Filter by rotation type. |\n" +
	"| last_import_status   | string  | Filter by last import status. |\n" +
	"| KeyMaterialId        | string  | Filter by key material ID. |"

var (
	_ datasource.DataSource              = &dataSourceAWSKeyRotationList{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSKeyRotationList{}
)

func NewDataSourceAWSKeyRotationList() datasource.DataSource {
	return &dataSourceAWSKeyRotationList{}
}

func (d *dataSourceAWSKeyRotationList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceAWSKeyRotationList struct {
	client *common.Client
}

type KeyRotationsDataSourceModel struct {
	KeyID     types.String       `tfsdk:"key_id"`
	Filters   types.Map          `tfsdk:"filters"`
	Rotations []KeyRotationTFSDK `tfsdk:"rotations"`
	Matched   types.Int64        `tfsdk:"matched"`
}

func (d *dataSourceAWSKeyRotationList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key_rotation_list"
}

func (d *dataSourceAWSKeyRotationList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of AWS key rotations. " +
			"Supply a `filters` map of key/value pairs matching the CipherTrust Manager API query parameters " +
			"for listing AWS key rotations (such as `key_source`, `RotationType`, or `KeyMaterialState`). " +
			"Set `limit = \"-1\"` to return all matching rotations.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters for listing AWS key rotations." + awsKeyRotationFiltersTable,
			},
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager ID of an AWS key.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The total number of records matching the given filters.",
			},
			"rotations": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of AWS key rotations matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"account": schema.StringAttribute{
							Computed:    true,
							Description: "The account that owns this resource.",
						},
						"aws_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "AWS key-material attributes.",
							Attributes: map[string]schema.Attribute{
								"expiration_model": schema.StringAttribute{
									Computed:    true,
									Description: "The key expiry model of the key material. Only applicable to EXTERNAL SYMMETRIC_DEFAULT keys.",
								},
								"import_state": schema.StringAttribute{
									Computed:    true,
									Description: "The import state of the key material. Only applicable to EXTERNAL SYMMETRIC_DEFAULT keys.",
								},
								"key_id": schema.StringAttribute{
									Computed:    true,
									Description: "AWS key ID.",
								},
								"key_material_description": schema.StringAttribute{
									Computed:    true,
									Description: "User specified key material description. Only applicable to EXTERNAL SYMMETRIC_DEFAULT keys.",
								},
								"key_material_id": schema.StringAttribute{
									Computed:    true,
									Description: "AWS key material ID.",
								},
								"key_material_state": schema.StringAttribute{
									Computed:    true,
									Description: "The state of the key material.",
								},
								"rotation_date": schema.StringAttribute{
									Computed:    true,
									Description: "Date and time the key material rotation completed.",
								},
								"rotation_type": schema.StringAttribute{
									Computed:    true,
									Description: "Whether the key material rotation was a scheduled automatic rotation or an on-demand rotation.",
								},
								"valid_to": schema.StringAttribute{
									Computed:    true,
									Description: "Date and time the key material expires if 'expiration_model' is KEY_MATERIAL_EXPIRES.",
								},
							},
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the CipherTrust Manager resource for this rotation was created.",
						},
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The CipherTrust Manager ID for this rotation.",
						},
						"key_material_origin": schema.StringAttribute{
							Computed:    true,
							Description: "The origin of the key material.",
						},
						"key_source": schema.StringAttribute{
							Computed:    true,
							Description: "The CipherTrust Manager key source.",
						},
						"key_source_container_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager ID of the key source container.",
						},
						"key_source_container_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the CipherTrust Manager key source container.",
						},
						"kms_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager AWS KMS ID.",
						},
						"source_key_id": schema.StringAttribute{
							Computed:    true,
							Description: "The CipherTrust Manager ID of the key used for the key material.",
						},
						"source_key_name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the CipherTrust Manager key used for the key material.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the CipherTrust Manager resource for this rotation was updated.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager's unique identifier for the resource.",
						},
					},
				},
			},
		},
	}
}

// Read lists the rotation history for a given AWS key and populates Terraform state.
func (d *dataSourceAWSKeyRotationList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_aws_key_rotation_list.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_aws_key_rotation_list.go -> Read][" + id + "]")

	var state KeyRotationsDataSourceModel
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
	keyID := state.KeyID.ValueString()
	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/rotations", filters)
	if err != nil {
		d.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [data_source_aws_key_rotation_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read AWS key rotation list from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var rotations DataSourceKeyRotationsJSON
	err = json.Unmarshal([]byte(jsonStr), &rotations)
	if err != nil {
		d.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [data_source_aws_key_rotation_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read AWS key rotation list from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	for _, rotation := range rotations.Resources {
		keyTFSDK := KeyRotationTFSDK{
			Account: types.StringValue(rotation.Account),
			AwsParam: KeyRotationAwsParamTFSDK{
				ExpirationModel:        types.StringValue(rotation.ExpirationModel),
				ImportState:            types.StringValue(rotation.ImportState),
				KeyID:                  types.StringValue(rotation.KeyId),
				KeyMaterialDescription: types.StringValue(rotation.KeyMaterialDescription),
				KeyMaterialID:          types.StringValue(rotation.KeyMaterialID),
				KeyMaterialState:       types.StringValue(rotation.KeyMaterialState),
				RotationDate:           types.StringValue(rotation.RotationDate),
				RotationType:           types.StringValue(rotation.RotationType),
				ValidTo:                types.StringValue(rotation.ValidTo),
			},
			CreatedAt:              types.StringValue(rotation.CreatedAt),
			ID:                     types.StringValue(rotation.ID),
			KeyMaterialOrigin:      types.StringValue(rotation.KeyMaterialOrigin),
			KeySource:              types.StringValue(rotation.KeySource),
			KeySourceContainerID:   types.StringValue(rotation.KeySourceContainerID),
			KeySourceContainerName: types.StringValue(rotation.KeySourceContainerName),
			KmsID:                  types.StringValue(rotation.KmsID),
			SourceKeyID:            types.StringValue(rotation.SourceKeyID),
			SourceKeyName:          types.StringValue(rotation.SourceKeyName),
			UpdatedAt:              types.StringValue(rotation.UpdatedAt),
			URI:                    types.StringValue(rotation.URI),
		}
		state.Rotations = append(state.Rotations, keyTFSDK)
	}
	state.Matched = types.Int64Value(gjson.Get(jsonStr, "total").Int())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
