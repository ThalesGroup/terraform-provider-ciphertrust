package cckm

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"reflect"
)

// Ensure the implementation satisfies the expected interfaces
var _ basetypes.MapValuable = CustomMapValue{}

type CustomMapValue struct {
	basetypes.MapValue
}

func (v CustomMapValue) Equal(o attr.Value) bool {
	other, ok := o.(CustomMapValue)
	if !ok {
		return false
	}
	equal := reflect.DeepEqual(v.MapValue, other.MapValue)
	return equal
}

func (v CustomMapValue) Type(ctx context.Context) attr.Type {
	return CustomMapType{}
}
