package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestSchedulerDataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a scheduler resource to retrieve later
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "test_scheduler" {
  name        = "TestScheduler"
  operation   = "database_backup"
  description = "Test scheduler description"
  run_on      = "any"
  run_at      = "*/15 * * * *"
  database_backup_params = {
    backup_key   = "d370535b-a035-4251-9780-e608f713be77"
    connection   = "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"
    description  = "Backup parameters for testing"
    do_scp       = false
    scope        = "system"
    tied_to_hsm  = false
  }
}

data "ciphertrust_scheduler_list" "test_scheduler" {
 filters = {
  name = ciphertrust_scheduler.test_scheduler.name
  }
}
`,
				// Step 2: Verify the data source retrieves the correct values
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.ciphertrust_scheduler_list.test_scheduler", "scheduler.0.id"),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.test_scheduler", "scheduler.0.name", "TestScheduler"),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.test_scheduler", "scheduler.0.operation", "database_backup"),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.test_scheduler", "scheduler.0.run_at", "*/15 * * * *"),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.test_scheduler", "scheduler.0.database_backup_params.connection", "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.test_scheduler", "scheduler.0.database_backup_params.backup_key", "d370535b-a035-4251-9780-e608f713be77"),
					resource.TestCheckResourceAttr("data.ciphertrust_scheduler_list.test_scheduler", "scheduler.0.database_backup_params.description", "Backup parameters for testing"),
				),
			},
		},
	})
}
