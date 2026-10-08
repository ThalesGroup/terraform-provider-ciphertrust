package cckm

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// azureParamsView is a flattened, read-only view of the azure_params object.
// Missing or null parts are returned as null values.
type azureParamsView struct {
	Kty            types.String
	Curve          types.String
	KeyOps         types.List
	Enabled        types.Bool
	ExpirationDate types.String
	ActivationDate types.String
	KeySize        types.Int64
	Tags           types.Map
}

// objectAttrs returns the attributes of an object, or nil when it is null, unknown or not an object.
func objectAttrs(v attr.Value) map[string]attr.Value {
	obj, ok := v.(types.Object)
	if !ok || obj.IsNull() || obj.IsUnknown() {
		return nil
	}
	return obj.Attributes()
}

func attrString(m map[string]attr.Value, name string) types.String {
	if v, ok := m[name].(types.String); ok {
		return v
	}
	return types.StringNull()
}

func attrInt64(m map[string]attr.Value, name string) types.Int64 {
	if v, ok := m[name].(types.Int64); ok {
		return v
	}
	return types.Int64Null()
}

func attrBool(m map[string]attr.Value, name string) types.Bool {
	if v, ok := m[name].(types.Bool); ok {
		return v
	}
	return types.BoolNull()
}

func attrList(m map[string]attr.Value, name string) types.List {
	if v, ok := m[name].(types.List); ok {
		return v
	}
	return types.ListNull(types.StringType)
}

func attrMap(m map[string]attr.Value, name string) types.Map {
	if v, ok := m[name].(types.Map); ok {
		return v
	}
	return types.MapNull(types.StringType)
}

// newAzureParamsView flattens the azure_params object.
func newAzureParamsView(obj types.Object) azureParamsView {
	params := objectAttrs(obj)
	key := objectAttrs(params["key"])
	attrs := objectAttrs(params["attributes"])
	return azureParamsView{
		Kty:            attrString(key, "kty"),
		Curve:          attrString(key, "curve"),
		KeyOps:         attrList(key, "key_ops"),
		Enabled:        attrBool(attrs, "enabled"),
		ExpirationDate: attrString(attrs, "expiration_date"),
		ActivationDate: attrString(attrs, "activation_date"),
		KeySize:        attrInt64(params, "key_size"),
		Tags:           attrMap(params, "tags"),
	}
}

func azureParamsPath(parts ...string) path.Path {
	p := path.Root("azure_params")
	for _, part := range parts {
		p = p.AtName(part)
	}
	return p
}
