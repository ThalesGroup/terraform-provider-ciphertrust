package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceScheduler(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a scheduler resource
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "scheduler" {
  name        = "TestScheduler"
  operation   = "database_backup"
  description = "This is to backup db"
  run_on      = "any"
  run_at      = "*/15 * * * *"
  database_backup_params = {
    connection = "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"
    description = "sample description"
    do_scp = false
    scope = "system"
    tied_to_hsm = false
  }
}
`,
				// Step 2: Verify that the scheduler resource is created
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.scheduler", "id"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "operation", "database_backup"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_at", "*/15 * * * *"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_on", "any"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "database_backup_params.connection", "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "scheduler" {
  name        = "TestScheduler"
  operation   = "database_backup"
  description = "This is to backup db updated description"
  run_on      = "any"
  run_at      = "*/30 * * * *"
  database_backup_params = {
    connection = "f9a81705-2b73-4a9c-9ab3-d78502ff11f1"
    description = "updated backup description"
    do_scp = true
    scope = "system"
    tied_to_hsm = false
  }
}
`,
				// Step 3: Verify the updated fields
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_at", "*/30 * * * *"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "description", "This is to backup db updated description"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "database_backup_params.description", "updated backup description"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "database_backup_params.do_scp", "true"),
				),
			},
		},
	})
}

// TestAccScheduler_nameImmutable verifies that changing the name of a scheduler
// after creation produces a plan-time error, not a silent no-op.
func TestAccScheduler_nameImmutable(t *testing.T) {
	RequireCM(t)
	t.Log("======== CHECK: scheduler name immutable ========")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "sched" {
  name      = "tf-test-sched-immutable"
  operation = "database_backup"
  run_at    = "*/15 * * * *"
  database_backup_params = {
    scope = "system"
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.sched", "id"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.sched", "name", "tf-test-sched-immutable"),
				),
			},
			// Step 2: Attempt to rename — must produce a plan-time error
			{
				Config: providerConfig + `
resource "ciphertrust_scheduler" "sched" {
  name      = "tf-test-sched-renamed"
  operation = "database_backup"
  run_at    = "*/15 * * * *"
  database_backup_params = {
    scope = "system"
  }
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Name cannot be changed"),
			},
		},
	})
	t.Log("======== PASSED: scheduler name immutable ========")
}

// terraform destroy will perform automatically at the end of the test
