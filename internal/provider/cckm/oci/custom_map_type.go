package cckm

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"reflect"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Ensure the implementation satisfies the expected interfaces

var _ basetypes.MapTypable = CustomMapType{}

type CustomMapType struct {
	basetypes.MapType
}

func (t CustomMapType) Equal(o attr.Type) bool {
	other, ok := o.(CustomMapType)
	if !ok {
		return false
	}
	equal := reflect.DeepEqual(t.MapType, other.MapType)
	return equal
}

func (t CustomMapType) String() string {
	return "CustomMapType"
}

func (t CustomMapType) ValueFromMap(ctx context.Context, in basetypes.MapValue) (basetypes.MapValuable, diag.Diagnostics) {
	var diags diag.Diagnostics
	var x basetypes.MapValuable
	if in.IsNull() {
		return x, diags
	}
	if in.IsUnknown() {
		return basetypes.NewMapUnknown(basetypes.StringType{}), diags
	}
	mapValue, d := basetypes.NewMapValue(types.StringType, in.Elements())
	if d.HasError() {
		return basetypes.NewMapNull(basetypes.StringType{}), d
	}
	return CustomMapValue{MapValue: mapValue}, diags
}

func (t CustomMapType) ValueFromTerraform(ctx context.Context, in tftypes.Value) (attr.Value, error) {
	attrValue, err := t.MapType.ValueFromTerraform(ctx, in)
	if err != nil {
		return nil, err
	}
	mapValue, ok := attrValue.(basetypes.MapValue)
	if !ok {
		return nil, fmt.Errorf("unexpected value type of %T", attrValue)
	}
	mapValuable, diags := t.ValueFromMap(ctx, mapValue)
	if diags.HasError() {
		return nil, fmt.Errorf("unexpected error converting MapValue to MapValuable: %v", diags)
	}
	return mapValuable, nil
}

func (t CustomMapType) ValueType(ctx context.Context) attr.Value {
	// CustomMapValue defined in the value type section
	return CustomMapValue{}
}
