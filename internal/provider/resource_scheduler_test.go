package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
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
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping TestAccScheduler_nameImmutable: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable (requires scheduler license)")
	}
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

// TestCipherTrust_Scheduler_ImmutableFields verifies that the operation field
// cannot be changed after scheduler creation (ImmutableString modifier).
// Requires a CipherTrust license that permits scheduler creation.
// Set CIPHERTRUST_SCHEDULER_ENABLED=1 to opt in; the test is skipped otherwise
// to avoid failing in environments where the license is absent.
func TestCipherTrust_Scheduler_ImmutableFields(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping TestCipherTrust_Scheduler_ImmutableFields: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	uniqueName := "immut-sched-" + uuid.New().String()[:8]
	uniqueName2 := "immut-sched-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Scenario A Step 1: create baseline using database_backup
			{
				Config: schedulerConfigOp(uniqueName, "database_backup", "0 0 * * *"),
			},
			// Scenario A Step 2: attempt to change operation — must produce immutability error, NOT destroy+recreate
			// (PlanOnly: ImmutableString fires at plan time before any API call, so the target
			// operation value "cckm_synchronization" does not need a CCKM license to test the modifier.)
			{
				Config:      schedulerConfigOp(uniqueName, "cckm_synchronization", "0 0 * * *"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
			// Scenario B Step 1: create second resource with cckm_key_rotation baseline
			{
				Config: schedulerConfigKeyRotation(uniqueName2, "0 0 * * *", false),
			},
			// Scenario B Step 2: attempt to change cckm_key_rotation_params — must produce immutability error
			{
				Config:      schedulerConfigKeyRotation(uniqueName2, "0 0 * * *", true),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

func schedulerConfigOp(name, operation, runAt string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test_op" {
  name      = %q
  operation = %q
  run_at    = %q
  database_backup_params = {
    scope = "system"
  }
}`, name, operation, runAt)
}

func schedulerConfigOpDB(name, operation, runAt string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test_key_rotation" {
  name      = %q
  operation = %q
  run_at    = %q
  database_backup_params = {
    scope = "system"
  }
}`, name, operation, runAt)
}

func schedulerConfigKeyRotation(name, runAt string, retainAlias bool) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "test_key_rotation" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = %q
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    aws_retain_alias = %t
  }
}`, name, runAt, retainAlias)
}

// terraform destroy will perform automatically at the end of the test
