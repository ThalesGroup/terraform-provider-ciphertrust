package cckm

// aws_objects.go centralises all Framework attr.Type maps and typed Object
// conversion helpers (FromObject / ToObject / extract / pack) for the AWS key
// nested blocks.  Having them in one file makes it easy to grep for the
// definition of any type map or helper without hunting across multiple resource
// files.

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

// ---------------------------------------------------------------------------
// Native (AWS_KMS) and BYOK (EXTERNAL) key aws_param - shared base type map
// ---------------------------------------------------------------------------

// commonAwsParamAttrTypes is the attr.Type map for the aws_param fields shared
// by both the aws_key and aws_byok_key resources. Use this as a base when
// building the full attr.Type map for each resource's aws_param block.
var commonAwsParamAttrTypes = map[string]attr.Type{
	"alias":                              types.SetType{ElemType: types.StringType},
	"arn":                                types.StringType,
	"aws_account_id":                     types.StringType,
	"key_id":                             types.StringType,
	"bypass_policy_lockout_safety_check": types.BoolType,
	"current_key_material_id":            types.StringType,
	"customer_master_key_spec":           types.StringType,
	"deletion_date":                      types.StringType,
	"description":                        types.StringType,
	"enabled":                            types.BoolType,
	"encryption_algorithms":              types.ListType{ElemType: types.StringType},
	"expiration_model":                   types.StringType,
	"key_manager":                        types.StringType,
	"key_rotation_enabled":               types.BoolType,
	"key_state":                          types.StringType,
	"key_usage":                          types.StringType,
	"mac_algorithms":                     types.ListType{ElemType: types.StringType},
	"multi_region":                       types.BoolType,
	"origin":                             types.StringType,
	"policy":                             types.StringType,
	"replica_policy":                     types.StringType,
	"replica_tags":                       types.StringType,
	"tags":                               types.MapType{ElemType: types.StringType},
}

// ---------------------------------------------------------------------------
// Native key (aws_key) aws_param
// ---------------------------------------------------------------------------

// nativeKeyAwsParamAttrTypes is the attr.Type map for the aws_param block of
// the aws_key resource. It extends commonAwsParamAttrTypes with two
// additional fields that only apply to native (AWS_KMS) keys:
//   - auto_rotation_period_in_days: Optional/Computed rotation period in days
//   - next_rotation_date: Computed date of the next scheduled AWS auto-rotation
var nativeKeyAwsParamAttrTypes = func() map[string]attr.Type {
	m := make(map[string]attr.Type, len(commonAwsParamAttrTypes)+2)
	for k, v := range commonAwsParamAttrTypes {
		m[k] = v
	}
	m["auto_rotation_period_in_days"] = types.Int64Type
	m["next_rotation_date"] = types.StringType
	return m
}()

// nativeKeyAwsParamFromObject decodes a types.Object plan/state value into
// *AWSKeyAwsParamTFSDK. Returns nil when the object is null or unknown
// (aws_param was not set in config or not yet known).
func nativeKeyAwsParamFromObject(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *AWSKeyAwsParamTFSDK {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var p AWSKeyAwsParamTFSDK
	diags.Append(obj.As(ctx, &p, basetypes.ObjectAsOptions{})...)
	return &p
}

// nativeKeyAwsParamToObject converts *AWSKeyAwsParamTFSDK to a types.Object
// for storage in state. Returns a typed null object when p is nil.
func nativeKeyAwsParamToObject(ctx context.Context, p *AWSKeyAwsParamTFSDK, diags *diag.Diagnostics) types.Object {
	if p == nil {
		return types.ObjectNull(nativeKeyAwsParamAttrTypes)
	}
	obj, d := types.ObjectValueFrom(ctx, nativeKeyAwsParamAttrTypes, p)
	diags.Append(d...)
	return obj
}

// ---------------------------------------------------------------------------
// BYOK key (aws_byok_key) aws_param
// ---------------------------------------------------------------------------

// byokAwsParamAttrTypes is the attr.Type map for the aws_param block of the
// aws_byok_key resource. It extends commonAwsParamAttrTypes with one
// additional field:
//   - valid_to: Optional/Computed expiry date for key material
//
// Note: auto_rotation_period_in_days and next_rotation_date are NOT included
// here because AWS cannot automatically rotate EXTERNAL-origin (BYOK) keys -
// they require customer-supplied key material and do not support on-demand
// AWS auto-rotation.
var byokAwsParamAttrTypes = func() map[string]attr.Type {
	m := make(map[string]attr.Type, len(commonAwsParamAttrTypes)+1)
	for k, v := range commonAwsParamAttrTypes {
		m[k] = v
	}
	m["valid_to"] = types.StringType
	return m
}()

// byokAwsParamFromObject decodes a types.Object plan/state value into
// *AWSByokAwsParamTFSDK. Returns nil when the object is null or unknown
// (aws_param was not set in config or not yet known).
func byokAwsParamFromObject(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *AWSByokAwsParamTFSDK {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var p AWSByokAwsParamTFSDK
	diags.Append(obj.As(ctx, &p, basetypes.ObjectAsOptions{})...)
	return &p
}

// byokAwsParamToObject converts *AWSByokAwsParamTFSDK to a types.Object for
// storage in state. Returns a typed null object when p is nil.
func byokAwsParamToObject(ctx context.Context, p *AWSByokAwsParamTFSDK, diags *diag.Diagnostics) types.Object {
	if p == nil {
		return types.ObjectNull(byokAwsParamAttrTypes)
	}
	obj, d := types.ObjectValueFrom(ctx, byokAwsParamAttrTypes, p)
	diags.Append(d...)
	return obj
}

// ---------------------------------------------------------------------------
// XKS key aws_param
// ---------------------------------------------------------------------------

// keyStoreCommonAwsParamAttrTypes is the attr.Type map for the fields shared by
// the aws_param block of both aws_xks_key and aws_cloudhsm_key resources.
var keyStoreCommonAwsParamAttrTypes = map[string]attr.Type{
	"alias":                    types.SetType{ElemType: types.StringType},
	"arn":                      types.StringType,
	"aws_account_id":           types.StringType,
	"aws_custom_key_store_id":  types.StringType,
	"customer_master_key_spec": types.StringType,
	"creation_date":            types.StringType,
	"deletion_date":            types.StringType,
	"description":              types.StringType,
	"enabled":                  types.BoolType,
	"encryption_algorithms":    types.ListType{ElemType: types.StringType},
	"expiration_model":         types.StringType,
	"key_id":                   types.StringType,
	"key_manager":              types.StringType,
	"key_state":                types.StringType,
	"key_usage":                types.StringType,
	"mac_algorithms":           types.ListType{ElemType: types.StringType},
	"origin":                   types.StringType,
	"policy":                   types.StringType,
	"tags":                     types.MapType{ElemType: types.StringType},
}

// xksKeyConfigAttrTypes is the attr.Type map for the xks_key_configuration nested object.
// It mirrors XksKeyConfigurationTFSDK.
var xksKeyConfigAttrTypes = map[string]attr.Type{
	"id": types.StringType,
}

// xksKeyAwsParamAttrTypes is the attr.Type map for the aws_param block of the
// aws_xks_key resource. Extends keyStoreCommonAwsParamAttrTypes with xks_key_configuration
// as a nested object (ObjectType).
var xksKeyAwsParamAttrTypes = func() map[string]attr.Type {
	m := make(map[string]attr.Type, len(keyStoreCommonAwsParamAttrTypes)+1)
	for k, v := range keyStoreCommonAwsParamAttrTypes {
		m[k] = v
	}
	m["xks_key_configuration"] = types.ObjectType{AttrTypes: xksKeyConfigAttrTypes}
	return m
}()

// extractXKSKeyAwsParam decodes a types.Object into *AWSXKSKeyAwsParamTFSDK.
// Returns nil when the object is null or unknown.
func extractXKSKeyAwsParam(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *AWSXKSKeyAwsParamTFSDK {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var p AWSXKSKeyAwsParamTFSDK
	diags.Append(obj.As(ctx, &p, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true, UnhandledUnknownAsEmpty: true})...)
	return &p
}

// packXKSKeyAwsParam converts *AWSXKSKeyAwsParamTFSDK to a types.Object for state storage.
// Returns a typed null object when p is nil.
func packXKSKeyAwsParam(ctx context.Context, p *AWSXKSKeyAwsParamTFSDK, diags *diag.Diagnostics) types.Object {
	if p == nil {
		return types.ObjectNull(xksKeyAwsParamAttrTypes)
	}
	obj, d := types.ObjectValueFrom(ctx, xksKeyAwsParamAttrTypes, p)
	diags.Append(d...)
	return obj
}

// ---------------------------------------------------------------------------
// CloudHSM key aws_param
// ---------------------------------------------------------------------------

// cloudHSMKeyAwsParamAttrTypes is the attr.Type map for the aws_param block of the
// aws_cloudhsm_key resource. Extends keyStoreCommonAwsParamAttrTypes with key_rotation_enabled.
var cloudHSMKeyAwsParamAttrTypes = func() map[string]attr.Type {
	m := make(map[string]attr.Type, len(keyStoreCommonAwsParamAttrTypes)+1)
	for k, v := range keyStoreCommonAwsParamAttrTypes {
		m[k] = v
	}
	m["key_rotation_enabled"] = types.BoolType
	return m
}()

// extractCloudHSMKeyAwsParam decodes a types.Object into *AWSCloudHSMKeyAwsParamTFSDK.
// Returns nil when the object is null or unknown.
func extractCloudHSMKeyAwsParam(ctx context.Context, obj types.Object, diags *diag.Diagnostics) *AWSCloudHSMKeyAwsParamTFSDK {
	if obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	var p AWSCloudHSMKeyAwsParamTFSDK
	diags.Append(obj.As(ctx, &p, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true, UnhandledUnknownAsEmpty: true})...)
	return &p
}

// packCloudHSMKeyAwsParam converts *AWSCloudHSMKeyAwsParamTFSDK to a types.Object for state storage.
// Returns a typed null object when p is nil.
func packCloudHSMKeyAwsParam(ctx context.Context, p *AWSCloudHSMKeyAwsParamTFSDK, diags *diag.Diagnostics) types.Object {
	if p == nil {
		return types.ObjectNull(cloudHSMKeyAwsParamAttrTypes)
	}
	obj, d := types.ObjectValueFrom(ctx, cloudHSMKeyAwsParamAttrTypes, p)
	diags.Append(d...)
	return obj
}
