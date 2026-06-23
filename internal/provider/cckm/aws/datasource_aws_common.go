package cckm

import (
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// computedAwsParamDSSchemaAttributes returns the Computed-only datasource schema attributes
// for the aws_param block on the aws_key data source.
// These mirror commonAwsParamSchemaAttributes from resource_aws_common.go but use
// datasource/schema types and mark every field Computed (no Optional/Required).
func computedAwsParamDSSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"alias": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Alias(es) of the key.",
			Validators: []validator.Set{
				setvalidator.ValueStringsAre(
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`),
						"must only contain alphanumeric characters, forward slashes, underscores, and dashes",
					),
				),
			},
		},
		"arn": schema.StringAttribute{
			Computed:    true,
			Description: "Amazon Resource Name (ARN) of the key.",
		},
		"aws_custom_key_store_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS Custom Key Store ID associated with the key. Populated for XKS and CloudHSM keys.",
		},
		"creation_date": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key was created in AWS.",
		},
		"current_key_material_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS key material ID that is currently active for this key. Populated for EXTERNAL-origin keys.",
		},
		"customer_master_key_spec": schema.StringAttribute{
			Computed:    true,
			Description: "Whether the KMS key contains a symmetric key or an asymmetric key pair.",
		},
		"deletion_date": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key is scheduled for deletion. Populated only when pending deletion.",
		},
		"description": schema.StringAttribute{
			Computed:    true,
			Description: "Description of the AWS key.",
		},
		"enabled": schema.BoolAttribute{
			Computed:    true,
			Description: "True if the key is enabled in AWS.",
		},
		"encryption_algorithms": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Encryption algorithms supported by the key. Populated for asymmetric keys.",
		},
		"expiration_model": schema.StringAttribute{
			Computed:    true,
			Description: "Expiration model for EXTERNAL-origin keys.",
		},
		"key_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS key ID.",
		},
		"key_manager": schema.StringAttribute{
			Computed:    true,
			Description: "Key manager (e.g. CUSTOMER).",
		},
		"key_rotation_enabled": schema.BoolAttribute{
			Computed:    true,
			Description: "True if AWS automatic key rotation is enabled.",
		},
		"key_state": schema.StringAttribute{
			Computed:    true,
			Description: "State of the key in AWS (e.g. Enabled, Disabled, PendingDeletion).",
		},
		"key_usage": schema.StringAttribute{
			Computed:    true,
			Description: "Specifies the intended use of the key.",
		},
		"mac_algorithms": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "MAC algorithms supported by the key. Populated for HMAC keys.",
		},
		"multi_region": schema.BoolAttribute{
			Computed:    true,
			Description: "True if this is a multi-region key.",
		},
		"multi_region_configuration": schema.SingleNestedAttribute{
			Computed:    true,
			Description: "Multi-region configuration for primary and replica keys.",
			Attributes: map[string]schema.Attribute{
				"multi_region_key_type": schema.StringAttribute{
					Computed:    true,
					Description: "Whether this is a PRIMARY or REPLICA multi-region key.",
				},
				"primary_key": schema.SingleNestedAttribute{
					Computed: true,
					Attributes: map[string]schema.Attribute{
						"arn":    schema.StringAttribute{Computed: true, Description: "ARN of the primary key."},
						"region": schema.StringAttribute{Computed: true, Description: "Region of the primary key."},
					},
				},
				"replica_keys": schema.SetNestedAttribute{
					Computed:    true,
					Description: "Set of replica key ARN and region pairs.",
					NestedObject: schema.NestedAttributeObject{
						Attributes: map[string]schema.Attribute{
							"arn":    schema.StringAttribute{Computed: true, Description: "ARN of the replica key."},
							"region": schema.StringAttribute{Computed: true, Description: "Region of the replica key."},
						},
					},
				},
			},
		},
		"next_rotation_date": schema.StringAttribute{
			Computed:    true,
			Description: "Date of the next scheduled automatic rotation in AWS.",
		},
		"origin": schema.StringAttribute{
			Computed:    true,
			Description: "Origin of the key material (e.g. AWS_KMS, EXTERNAL).",
		},
		"policy": schema.StringAttribute{
			Computed:    true,
			Description: "Resulting AWS key policy.",
		},
		"replica_policy": schema.StringAttribute{
			Computed:    true,
			Description: "Key policy applied to replica keys. Populated for multi-region primary keys.",
		},
		"replica_tags": schema.StringAttribute{
			Computed:    true,
			Description: "Tags applied to replica keys. Raw JSON string. Populated for multi-region primary keys.",
		},
		"rotation_period_in_days": schema.Int64Attribute{
			Computed:    true,
			Description: "Rotation period in days configured in AWS for this key.",
		},
		"tags": schema.MapAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Tags assigned to the AWS key.",
		},
		"valid_to": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key material expires. Populated for EXTERNAL-origin keys with an expiry.",
		},
		"xks_key_configuration": schema.StringAttribute{
			Computed:    true,
			Description: "XKS key configuration details. Populated for keys in an external key store. Raw JSON string.",
		},
	}
}

// computedKeyStoreAwsParamDSSchemaAttributes returns the Computed-only datasource schema
// attributes for the aws_param block on the aws_xks_key and aws_cloudhsm_key data sources.
// The expanded set mirrors AWSKeyStoreDSAwsParamTFSDK - it includes all computed fields
// returned by the CCKM API for key-store keys.
// key_rotation_enabled is populated for CloudHSM keys only; xks_key_configuration for XKS only.
func computedKeyStoreAwsParamDSSchemaAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"alias": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Alias(es) assigned to the key. Populated for linked keys.",
			Validators: []validator.Set{
				setvalidator.ValueStringsAre(
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`),
						"must only contain alphanumeric characters, forward slashes, underscores, and dashes",
					),
				),
			},
		},
		"description": schema.StringAttribute{
			Computed:    true,
			Description: "Description of the AWS key.",
		},
		"tags": schema.MapAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Tags assigned to the key. Populated for linked keys.",
		},
		"arn": schema.StringAttribute{
			Computed:    true,
			Description: "Amazon Resource Name (ARN) of the key.",
		},
		"aws_account_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS account ID.",
		},
		"aws_custom_key_store_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS Custom Key Store ID associated with the key.",
		},
		"customer_master_key_spec": schema.StringAttribute{
			Computed:    true,
			Description: "Whether the KMS key contains a symmetric key or an asymmetric key pair.",
		},
		"creation_date": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key was created in AWS.",
		},
		"deletion_date": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key is scheduled for deletion. Populated only when pending deletion.",
		},
		"enabled": schema.BoolAttribute{
			Computed:    true,
			Description: "True if the key is enabled in AWS.",
		},
		"encryption_algorithms": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Encryption algorithms supported by the key. Populated for asymmetric keys.",
		},
		"expiration_model": schema.StringAttribute{
			Computed:    true,
			Description: "Expiration model for the key material.",
		},
		"key_id": schema.StringAttribute{
			Computed:    true,
			Description: "AWS key ID.",
		},
		"key_manager": schema.StringAttribute{
			Computed:    true,
			Description: "Key manager (e.g. CUSTOMER).",
		},
		// key_rotation_enabled is populated for CloudHSM keys; will be false for XKS keys.
		"key_rotation_enabled": schema.BoolAttribute{
			Computed:    true,
			Description: "True if AWS automatic key rotation is enabled. Populated for CloudHSM keys.",
		},
		"key_state": schema.StringAttribute{
			Computed:    true,
			Description: "State of the key in AWS (e.g. Enabled, Disabled, PendingDeletion).",
		},
		"key_usage": schema.StringAttribute{
			Computed:    true,
			Description: "Intended use of the key (e.g. ENCRYPT_DECRYPT).",
		},
		"mac_algorithms": schema.ListAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "MAC algorithms supported by the key. Populated for HMAC keys.",
		},
		"origin": schema.StringAttribute{
			Computed:    true,
			Description: "Origin of the key material (e.g. EXTERNAL_KEY_STORE, AWS_CLOUDHSM).",
		},
		"policy": schema.StringAttribute{
			Computed:    true,
			Description: "Resulting AWS key policy.",
		},
		// xks_key_configuration is populated for XKS keys; will be empty for CloudHSM keys.
		"xks_key_configuration": schema.StringAttribute{
			Computed:    true,
			Description: "XKS key configuration details. Raw JSON string. Populated for XKS keys.",
		},
	}
}

// commonKeyListItemAttributes returns the Computed-only schema attributes shared by all
// three AWS key list data source item types (aws_key, aws_xks_key, aws_cloudhsm_key).
// Only non-aws_param fields are included here.
func commonKeyListItemAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			Computed:    true,
			Description: "Terraform ID (composite of region and AWS key ID for aws_key).",
		},
		"region": schema.StringAttribute{
			Computed:    true,
			Description: "AWS region the key belongs to.",
		},
		"cloud_name": schema.StringAttribute{
			Computed:    true,
			Description: "AWS cloud.",
		},
		"created_at": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key was created.",
		},
		"external_accounts": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Other AWS accounts that have access to this key.",
		},
		"key_admins": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Key administrators - users.",
		},
		"key_admins_roles": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Key administrators - roles.",
		},
		"key_id": schema.StringAttribute{
			Computed:    true,
			Description: "CipherTrust Manager Key ID.",
		},
		"key_material_origin": schema.StringAttribute{
			Computed:    true,
			Description: "Key material origin.",
		},
		"key_source": schema.StringAttribute{
			Computed:    true,
			Description: "Source of the key.",
		},
		"key_type": schema.StringAttribute{
			Computed:    true,
			Description: "Key type.",
		},
		"key_users": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Key users - users.",
		},
		"key_users_roles": schema.SetAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "Key users - roles.",
		},
		"labels": schema.MapAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "A list of key:value pairs associated with the key.",
		},
		"local_key_id": schema.StringAttribute{
			Computed:    true,
			Description: "CipherTrust Manager key identifier of the external key.",
		},
		"local_key_name": schema.StringAttribute{
			Computed:    true,
			Description: "CipherTrust Manager key name of the external key.",
		},
		"policy_template_tag": schema.MapAttribute{
			Computed:    true,
			ElementType: types.StringType,
			Description: "AWS key tag for an associated policy template.",
		},
		"rotated_at": schema.StringAttribute{
			Computed:    true,
			Description: "Time when this key was rotated by a scheduled rotation job.",
		},
		"rotated_from": schema.StringAttribute{
			Computed:    true,
			Description: "CipherTrust Manager key ID of the key this key was rotated from.",
		},
		"rotated_to": schema.StringAttribute{
			Computed:    true,
			Description: "CipherTrust Manager key ID which this key was rotated to.",
		},
		"rotation_status": schema.StringAttribute{
			Computed:    true,
			Description: "Rotation status of the key.",
		},
		"synced_at": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key was synchronized.",
		},
		"updated_at": schema.StringAttribute{
			Computed:    true,
			Description: "Date the key was last updated.",
		},
	}
}

// awsKeyListItemAttributes returns the Computed-only schema attributes for each item
// in the aws_key list data source. It combines common key attributes with aws_key-specific
// attributes (auto_rotate, kms, multi_region, multi_region_configuration, next_rotation_date)
// and the computed aws_param block.
func awsKeyListItemAttributes() map[string]schema.Attribute {
	attrs := commonKeyListItemAttributes()
	attrs["auto_rotate"] = schema.BoolAttribute{
		Computed:    true,
		Description: "True if AWS autorotation is enabled on the key.",
	}
	attrs["auto_rotation_period_in_days"] = schema.Int64Attribute{
		Computed:    true,
		Description: "Rotation period in days.",
	}
	attrs["kms_name"] = schema.StringAttribute{
		Computed:    true,
		Description: "Name of the KMS. On input this accepts a KMS name or ID; the returned value is the KMS name.",
	}
	attrs["kms_id"] = schema.StringAttribute{
		Computed:    true,
		Description: "ID of the KMS.",
	}
	attrs["multi_region"] = schema.BoolAttribute{
		Computed:    true,
		Description: "True if this is a multi-region key.",
	}
	attrs["multi_region_configuration"] = schema.SingleNestedAttribute{
		Computed:    true,
		Description: "Multi-region configuration for the key.",
		Attributes: map[string]schema.Attribute{
			"multi_region_key_type": schema.StringAttribute{
				Computed:    true,
				Description: "Whether this key is PRIMARY or REPLICA.",
			},
			"primary_key": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "ARN and region of the primary key.",
				Attributes: map[string]schema.Attribute{
					"arn":    schema.StringAttribute{Computed: true, Description: "ARN of the primary key."},
					"region": schema.StringAttribute{Computed: true, Description: "Region of the primary key."},
				},
			},
			"replica_keys": schema.SetNestedAttribute{
				Computed:    true,
				Description: "ARN and region of each replica key.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"arn":    schema.StringAttribute{Computed: true, Description: "ARN of the replica key."},
						"region": schema.StringAttribute{Computed: true, Description: "Region of the replica key."},
					},
				},
			},
		},
	}
	attrs["next_rotation_date"] = schema.StringAttribute{
		Computed:    true,
		Description: "Date when auto-rotation will happen next.",
	}
	attrs["aws_param"] = schema.SingleNestedAttribute{
		Computed:    true,
		Description: "AWS key parameters returned by the API.",
		Attributes:  computedAwsParamDSSchemaAttributes(),
	}
	return attrs
}

// awsKeyStoreListItemAttributes returns the Computed-only schema attributes common to
// both aws_xks_key and aws_cloudhsm_key list item objects. It combines the common key
// attributes with keystore-specific computed fields and the aws_param block.
func awsKeyStoreListItemAttributes() map[string]schema.Attribute {
	attrs := commonKeyListItemAttributes()
	attrs["kms_name"] = schema.StringAttribute{
		Computed:    true,
		Description: "Name of the KMS. On input this accepts a KMS name or ID; the returned value is the KMS name.",
	}
	attrs["kms_id"] = schema.StringAttribute{
		Computed:    true,
		Description: "ID of the KMS.",
	}
	attrs["custom_key_store_id"] = schema.StringAttribute{
		Computed:    true,
		Description: "Custom keystore ID in AWS.",
	}
	attrs["linked"] = schema.BoolAttribute{
		Computed:    true,
		Description: "True if the key is linked with AWS.",
	}
	attrs["blocked"] = schema.BoolAttribute{
		Computed:    true,
		Description: "True if the key is blocked for any data plane operation.",
	}
	attrs["aws_custom_key_store_id"] = schema.StringAttribute{
		Computed:    true,
		Description: "Custom keystore ID in AWS.",
	}
	attrs["aws_param"] = schema.SingleNestedAttribute{
		Computed:    true,
		Description: "AWS key parameters returned by the API.",
		Attributes:  computedKeyStoreAwsParamDSSchemaAttributes(),
	}
	return attrs
}

// awsXKSKeyListItemAttributes returns the Computed-only schema attributes for each item
// in the aws_xks_key list data source.
func awsXKSKeyListItemAttributes() map[string]schema.Attribute {
	attrs := awsKeyStoreListItemAttributes()
	attrs["aws_xks_key_id"] = schema.StringAttribute{
		Computed:    true,
		Description: "XKS key ID in AWS.",
	}
	attrs["source_key_tier"] = schema.StringAttribute{
		Computed:    true,
		Description: "Source key tier for AWS XKS key.",
	}
	return attrs
}
