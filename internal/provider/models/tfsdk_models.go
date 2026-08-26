package models

import "github.com/hashicorp/terraform-plugin-framework/types"

type DataTransformationRule struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type IDTKeyRule struct {
	CurrentKey            types.String `tfsdk:"current_key"`
	CurrentKeyType        types.String `tfsdk:"current_key_type"`
	TransformationKey     types.String `tfsdk:"transformation_key"`
	TransformationKeyType types.String `tfsdk:"transformation_key_type"`
}

type CurrentKey struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type TransformationKey struct {
	KeyID   types.String `tfsdk:"key_id"`
	KeyType types.String `tfsdk:"key_type"`
}

type LDTKeyRule struct {
	CurrentKey        CurrentKey        `tfsdk:"current_key"`
	TransformationKey TransformationKey `tfsdk:"transformation_key"`
	IsExclusionRule   types.Bool        `tfsdk:"is_exclusion_rule"`
	ResourceSetID     types.String      `tfsdk:"resource_set_id"`
}

type CTEPolicyMetadata struct {
	RestrictUpdate types.Bool `tfsdk:"restrict_update"`
}

type SecurityRule struct {
	Action             types.String `tfsdk:"action"`
	Effect             types.String `tfsdk:"effect"`
	ExcludeProcessSet  types.Bool   `tfsdk:"exclude_process_set"`
	ExcludeResourceSet types.Bool   `tfsdk:"exclude_resource_set"`
	ExcludeUserSet     types.Bool   `tfsdk:"exclude_user_set"`
	PartialMatch       types.Bool   `tfsdk:"partial_match"`
	ProcessSetID       types.String `tfsdk:"process_set_id"`
	ResourceSetID      types.String `tfsdk:"resource_set_id"`
	UserSetID          types.String `tfsdk:"user_set_id"`
}

type SignatureRule struct {
	SignatureSetID types.String `tfsdk:"signature_set_id"`
}

type KeyRule struct {
	KeyID         types.String `tfsdk:"key_id"`
	KeyType       types.String `tfsdk:"key_type"`
	ResourceSetID types.String `tfsdk:"resource_set_id"`
}

type ClassificationTagAttributes struct {
	DataType types.String `tfsdk:"data_type"`
	Name     types.String `tfsdk:"name"`
	Operator types.String `tfsdk:"operator"`
	Value    types.String `tfsdk:"value"`
}

type ClassificationTag struct {
	Description types.String                  `tfsdk:"description"`
	Name        types.String                  `tfsdk:"name"`
	Attributes  []ClassificationTagAttributes `tfsdk:"attributes"`
}

type CTEResource struct {
	Directory         types.String `tfsdk:"directory"`
	File              types.String `tfsdk:"file"`
	HDFS              types.Bool   `tfsdk:"hdfs"`
	IncludeSubfolders types.Bool   `tfsdk:"include_subfolders"`
}
