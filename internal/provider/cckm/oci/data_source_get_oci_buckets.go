package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceGetOCIBuckets{}
	_ datasource.DataSourceWithConfigure = &dataSourceGetOCIBuckets{}
)

func NewDataSourceGetOCIBuckets() datasource.DataSource {
	return &dataSourceGetOCIBuckets{}
}

type dataSourceGetOCIBuckets struct {
	client *common.Client
}

func (d *dataSourceGetOCIBuckets) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *dataSourceGetOCIBuckets) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_get_oci_buckets"
}

func (d *dataSourceGetOCIBuckets) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI object storage buckets available to the connection in the given compartment.",
		Attributes: map[string]schema.Attribute{
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager OCI connection name or ID.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
			},
			"compartment_id": schema.StringAttribute{
				Required:    true,
				Description: "Compartment OCID whose buckets are to be listed.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
			},
			"buckets": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of OCI object storage buckets.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"namespace": schema.StringAttribute{
							Computed:    true,
							Description: "The Object Storage namespace of the bucket.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The name of the bucket.",
						},
						"compartment_id": schema.StringAttribute{
							Computed:    true,
							Description: "The OCID of the compartment that contains the bucket.",
						},
						"time_created": schema.StringAttribute{
							Computed:    true,
							Description: "The date and time the bucket was created.",
						},
						"freeform_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "The freeform tags of the bucket.",
						},
						"defined_tags": schema.SetNestedAttribute{
							Computed:    true,
							Description: "The defined tags of the bucket.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"tag": schema.StringAttribute{
										Computed:    true,
										Description: "The tag's namespace.",
									},
									"values": schema.MapAttribute{
										Computed:    true,
										ElementType: types.StringType,
										Description: "The key:value pairs associated with the tag.",
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// Read retrieves all OCI buckets for the given connection and compartment,
// automatically paginating until all results are collected.
func (d *dataSourceGetOCIBuckets) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_get_oci_buckets.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_get_oci_buckets.go -> Read][" + id + "]")

	var state models.ListOCIBucketsTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := models.ListOCIBucketsPayloadJSON{
		Connection:    state.Connection.ValueString(),
		CompartmentID: state.CompartmentID.ValueString(),
	}

	var data []models.OCIBucketJSON
	for {
		page := d.fetchBuckets(ctx, id, payload, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if page == nil {
			break
		}
		data = append(data, page.Data...)
		if page.OciNextPage == "" {
			break
		}
		np := page.OciNextPage
		payload.OciNextPage = &np
	}

	state.Buckets = []models.OCIBucketTFSDK{}
	for _, b := range data {
		bucket := models.OCIBucketTFSDK{
			Namespace:     types.StringValue(b.Namespace),
			Name:          types.StringValue(b.Name),
			CompartmentID: types.StringValue(b.CompartmentID),
			TimeCreated:   types.StringValue(b.TimeCreated),
		}
		setFreeformTagsState(ctx, b.FreeformTags, &bucket.FreeformTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setDefinedTagsState(ctx, b.DefinedTags, &bucket.DefinedTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Buckets = append(state.Buckets, bucket)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// fetchBuckets marshals the payload, calls the CM OCI list-buckets endpoint,
// and unmarshals the response. Appends an error diagnostic on any failure.
func (d *dataSourceGetOCIBuckets) fetchBuckets(ctx context.Context, id string, payload models.ListOCIBucketsPayloadJSON, diags *diag.Diagnostics) *models.ListOCIBucketsResponseJSON {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading OCI buckets, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	response, err := d.client.PostDataV2(ctx, id, common.URL_OCI+"/storage/list-buckets", payloadJSON)
	if err != nil {
		msg := "Error reading OCI buckets."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	var result models.ListOCIBucketsResponseJSON
	err = json.Unmarshal([]byte(response), &result)
	if err != nil {
		msg := "Error reading OCI buckets, invalid data output."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	return &result
}
