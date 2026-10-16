package cckm

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

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
