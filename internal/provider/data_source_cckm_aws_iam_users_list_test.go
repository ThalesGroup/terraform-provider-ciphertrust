// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAWSDataSourceIAMUsersList(t *testing.T) {
	baseConfig, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	dsAll := `
		data "ciphertrust_aws_iam_users_list" "all" {
			kms_id = ciphertrust_aws_kms.kms.id
		}`

	dsMax5 := `
		data "ciphertrust_aws_iam_users_list" "max5" {
			kms_id    = ciphertrust_aws_kms.kms.id
			max_items = 5
		}`

	dsRandomPath := `
		data "ciphertrust_aws_iam_users_list" "random_path" {
			kms_id      = ciphertrust_aws_kms.kms.id
			path_prefix = "/random"
		}`

	dsAllName := "data.ciphertrust_aws_iam_users_list.all"
	dsMax5Name := "data.ciphertrust_aws_iam_users_list.max5"
	dsRandomPathName := "data.ciphertrust_aws_iam_users_list.random_path"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Fetch all users - expect at least one user returned.
				Config: baseConfig + dsAll,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(dsAllName, "users.0.arn"),
					resource.TestCheckResourceAttrSet(dsAllName, "users.0.user_name"),
				),
			},
			{
				// Fetch at most 5 users - expect exactly 5 (account has more than 5 users).
				Config: baseConfig + dsMax5,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dsMax5Name, "users.#", "5"),
				),
			},
			{
				// Fetch with a non-existent path prefix - expect zero users.
				Config: baseConfig + dsRandomPath,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(dsRandomPathName, "users.#", "0"),
				),
			},
		},
	})
}
