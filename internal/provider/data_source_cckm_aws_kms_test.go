package provider

import (
	"fmt"
	"github.com/google/uuid"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsDataSourceKms(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	kmsTwoConfig := `
		resource "ciphertrust_aws_kms" "kms_two" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection  = ciphertrust_aws_connection.aws_connection.id
			name           = "%s"
			regions = [
				data.ciphertrust_aws_account_details.account_details.regions[3],
				data.ciphertrust_aws_account_details.account_details.regions[4],
			]
		}`
	kmsTwoConfigStr := fmt.Sprintf(kmsTwoConfig, "tf-"+uuid.New().String()[:8])

	allKms := `
		data "ciphertrust_aws_kms" "all_kms" {
			depends_on = [ciphertrust_aws_kms.kms, ciphertrust_aws_kms.kms_two]
		}`
	byConnection := `
		data "ciphertrust_aws_kms" "by_connection" {
			depends_on = [ciphertrust_aws_kms.kms, ciphertrust_aws_kms.kms_two]
			aws_connection = ciphertrust_aws_connection.aws_connection.name
		}`

	byName := `
		data "ciphertrust_aws_kms" "by_name" {
			kms_name = ciphertrust_aws_kms.kms_two.name
		}`

	byID := `
		data "ciphertrust_aws_kms" "by_id" {
			kms_id = ciphertrust_aws_kms.kms.id
		}`

	dsAllKmsResource := "data.ciphertrust_aws_kms.all_kms"
	dsByConnection := "data.ciphertrust_aws_kms.by_connection"
	dsByName := "data.ciphertrust_aws_kms.by_name"
	dsByID := "data.ciphertrust_aws_kms.by_id"
	kmsOneResourceName := "ciphertrust_aws_kms.kms"
	kmsTwoResourceName := "ciphertrust_aws_kms.kms_two"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionResource + kmsTwoConfigStr + allKms,
				Check: resource.ComposeTestCheckFunc(
					testAccListResourceAttributes(dsAllKmsResource),
					resource.TestCheckResourceAttr(dsAllKmsResource, "kms.#", "2"),
				),
			},
			{
				Config: awsConnectionResource + kmsTwoConfigStr + byConnection,
				Check: resource.ComposeTestCheckFunc(
					testAccListResourceAttributes(dsByConnection),
					resource.TestCheckResourceAttr(dsByConnection, "kms.#", "2"),
				),
			},
			{
				Config: awsConnectionResource + kmsTwoConfigStr + byName,
				Check: resource.ComposeTestCheckFunc(
					testAccListResourceAttributes(dsByName),
					resource.TestCheckResourceAttr(dsByName, "kms.#", "1"),
					resource.TestCheckResourceAttrPair(dsByName, "kms.0.regions.#", kmsTwoResourceName, "regions.#"),
					resource.TestCheckResourceAttrPair(kmsTwoResourceName, "id", dsByName, "kms.0.kms_id"),
				),
			},
			{
				Config: awsConnectionResource + kmsTwoConfigStr + byID,
				Check: resource.ComposeTestCheckFunc(
					testAccListResourceAttributes(dsByID),
					resource.TestCheckResourceAttr(dsByID, "kms.#", "1"),
					resource.TestCheckResourceAttrPair(dsByID, "kms.0.regions.#", kmsOneResourceName, "regions.#"),
					resource.TestCheckResourceAttrPair(kmsOneResourceName, "id", dsByID, "kms.0.kms_id"),
				),
			},
		},
	})
}
