package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceOCICompartments{}
	_ datasource.DataSourceWithConfigure = &dataSourceOCICompartments{}
)

func NewDataSourceOCICompartments() datasource.DataSource {
	return &dataSourceOCICompartments{}
}

func (d *dataSourceOCICompartments) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceOCICompartments struct {
	client *common.Client
}

func (d *dataSourceOCICompartments) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_get_oci_compartments"
}

func (d *dataSourceOCICompartments) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI compartments available to the connection.",
		Attributes: map[string]schema.Attribute{
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager OCI connection name or ID.",
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of records to return in a paginated 'List' call. It might not return the exact number as the first page might return one more than provided limit because of the inclusion of the root compartment (tenancy).",
				Validators:  []validator.Int64{int64validator.AtLeast(1)},
			},
			"compartments": schema.ListNestedAttribute{
				Description: "A list of compartments available to the connection.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"compartment_id": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Computed: true,
						},
						"description": schema.StringAttribute{
							Computed: true,
						},
						"time_created": schema.StringAttribute{
							Computed: true,
						},
						"lifecycle_state": schema.StringAttribute{
							Computed: true,
						},
						"inactive_status": schema.Int64Attribute{
							Computed: true,
						},
						"is_accessible": schema.BoolAttribute{
							Computed: true,
						},
						"freeform_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
						"defined_tags": schema.MapAttribute{
							Computed: true,
							ElementType: types.MapType{
								ElemType: types.StringType,
							},
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceOCICompartments) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_oci_compartments.go -> Read]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_oci_compartments.go -> Read]")
	id := uuid.New().String()

	var state GetOCICompartmentsDataSourceModelTFSDK
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}
	connection := state.Connection.ValueString()
	payload := GetOCICompartmentsPayloadJSON{
		Connection: connection,
	}
	limit := state.Limit.ValueInt64()
	if limit != 0 {
		payload.Limit = &limit
	}

	var data []GetOCICompartmentJSON
	compartments := d.fetchCompartments(ctx, id, payload, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data = append(data, compartments.Data...)
	nextPage := compartments.NextPage
	for i := 0; nextPage != "" && (limit != 0 && int64(len(data)) < limit); i++ {
		payload.NextPage = &nextPage
		compartments = d.fetchCompartments(ctx, id, payload, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		data = append(data, compartments.Data...)
		nextPage = compartments.NextPage
	}

	// SARAH
	//definedTags := make(map[string]map[string]string)
	//definedTags["one"] = make(map[string]string)
	//definedTags["one"]["keyOne"] = "valueOne"
	//definedTags["one"]["keyTwo"] = "valueTwo"
	//
	//freeformTags := make(map[string]string)
	//freeformTags["ff_one"] = "ff_one"

	for _, compartment := range data {
		//compartment.DefinedTags = definedTags
		//compartment.FreeformTags = freeformTags

		compartmentTFSDK := GetOCICompartmentTFSDK{
			ID:             types.StringValue(compartment.ID),
			CompartmentID:  types.StringValue(compartment.CompartmentID),
			Name:           types.StringValue(compartment.Name),
			Description:    types.StringValue(compartment.Description),
			TimeCreated:    types.StringValue(compartment.TimeCreated),
			LifecycleState: types.StringValue(compartment.LifecycleState),
			InactiveStatus: types.Int64Value(compartment.InactiveStatus),
			IsAccessible:   types.BoolValue(compartment.IsAccessible),
		}

		freeFormTagsMap := make(map[string]attr.Value)
		if compartment.FreeformTags != nil {
			for key, value := range compartment.FreeformTags {
				freeFormTagsMap[key] = types.StringValue(value)
			}
		}
		var dg diag.Diagnostics
		compartmentTFSDK.FreeformTags, dg = types.MapValueFrom(ctx, types.StringType, freeFormTagsMap)
		if dg.HasError() {
			tflog.Error(ctx, fmt.Sprintf("An error occured creating freeform tag map for oci compartment: %s", compartment.Name))
			resp.Diagnostics.Append(dg...)
			return
		}

		compartmentTFSDK.DefinedTags = make(map[string]types.Map)
		if compartment.DefinedTags != nil {
			for key, value := range compartment.DefinedTags {
				var mapValues basetypes.MapValue
				mapValues, dg = types.MapValueFrom(ctx, types.StringType, value)
				if dg.HasError() {
					tflog.Error(ctx, fmt.Sprintf("An error occured creating defined tag map for oci compartment: %s", compartment.Name))
					resp.Diagnostics.Append(dg...)
					return
				}
				compartmentTFSDK.DefinedTags[key] = mapValues
			}
		}
		state.Compartments = append(state.Compartments, compartmentTFSDK)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (d *dataSourceOCICompartments) fetchCompartments(ctx context.Context, id string,
	payload GetOCICompartmentsPayloadJSON, diags *diag.Diagnostics) *GetOCICompartmentsJSON {

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading OCI compartments, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	response, err := d.client.PostDataV2(ctx, id, common.URL_OCI+"/get-compartments", payloadJSON)
	if err != nil {
		msg := "Error reading OCI compartments."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	var ociCompartments GetOCICompartmentsJSON
	err = json.Unmarshal([]byte(response), &ociCompartments)
	if err != nil {
		msg := "Error reading OCI compartments, invalid data output."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	return &ociCompartments
}
