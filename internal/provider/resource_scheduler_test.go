package provider

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// schedulerTestPrefixes lists all name prefixes used by acceptance tests when
// creating scheduler resources. Used by schedulerSweepAll to identify orphaned
// test schedulers that consume the CM license quota.
var schedulerTestPrefixes = []string{
	"tf-test-sched-",
	"tf-test-schedlist-",
	"sched-",
	"immut-sched-",
	"TestScheduler",
}

// schedulerSweepAll deletes all scheduler jobs whose names match a known test
// prefix from CM, clearing the CM license quota before a new test run.
// Uses a large limit to avoid pagination issues.
func schedulerSweepAll() {
	client, ok := createCMClient()
	if !ok {
		return
	}
	ctx := context.Background()
	filters := url.Values{}
	filters.Set("limit", "500")
	resp, err := client.ListWithFilters(ctx, uuid.New().String(), common.URL_SCHEDULER_JOB_CONFIGS, filters)
	if err != nil {
		// Fall back to GetAll if ListWithFilters fails
		resp, err = client.GetAll(ctx, uuid.New().String(), common.URL_SCHEDULER_JOB_CONFIGS)
		if err != nil {
			return
		}
	}
	// ListWithFilters returns the full body; GetAll returns just the resources array string.
	// Extract resources array regardless of which call succeeded.
	resources := gjson.Get(resp, "resources")
	if !resources.Exists() {
		// resp might already be the resources array (from GetAll fallback)
		resources = gjson.Parse(resp)
	}
	resources.ForEach(func(_, v gjson.Result) bool {
		name := v.Get("name").String()
		for _, prefix := range schedulerTestPrefixes {
			if strings.HasPrefix(name, prefix) || name == prefix {
				id := v.Get("id").String()
				if id == "" {
					return true
				}
				delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_SCHEDULER_JOB_CONFIGS, id)
				_, _ = client.DeleteByID(ctx, "DELETE", id, delURL, nil)
				break
			}
		}
		return true
	})
}

func Test_CM_ResourceScheduler(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_ResourceScheduler: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable (requires available scheduler license slot)")
	}
	name := "tf-test-sched-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create a scheduler resource
			{
				PreConfig: func() { schedulerSweepAll() },
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "scheduler" {
  name        = %q
  operation   = "database_backup"
  description = "This is to backup db"
  run_on      = "any"
  run_at      = "*/15 * * * *"
  database_backup_params = {
    scope = "system"
  }
}
`, name),
				// Verify that the scheduler resource is created
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.scheduler", "id"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "operation", "database_backup"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_at", "*/15 * * * *"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_on", "any"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "scheduler" {
  name        = %q
  operation   = "database_backup"
  description = "This is to backup db updated description"
  run_on      = "any"
  run_at      = "*/30 * * * *"
  database_backup_params = {
    scope = "system"
  }
}
`, name),
				// Verify the updated fields
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "run_at", "*/30 * * * *"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.scheduler", "description", "This is to backup db updated description"),
				),
			},
		},
	})
}

// Test_CM_AccScheduler_nameImmutable verifies that changing the name of a scheduler
// after creation produces a plan-time error, not a silent no-op.
func Test_CM_AccScheduler_nameImmutable(t *testing.T) {
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

// Test_CM_CipherTrust_Scheduler_ImmutableFields verifies that the operation field cannot be
// changed after scheduler creation (ImmutableString modifier). Requires a CipherTrust license
// that permits scheduler creation; set CIPHERTRUST_SCHEDULER_ENABLED=1 to opt in.
func Test_CM_CipherTrust_Scheduler_ImmutableFields(t *testing.T) {
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

// schedulerDatesConfig returns HCL for a database_backup scheduler. Pass "omit"
// for startDate or endDate to exclude the field from the config entirely (null semantics).
// Pass "" to explicitly clear a previously-set value. Pass a date string to set it.
func schedulerDatesConfig(name, startDate, endDate string) string {
	var startLine, endLine string
	if startDate != "omit" {
		startLine = fmt.Sprintf("  start_date = %q\n", startDate)
	}
	if endDate != "omit" {
		endLine = fmt.Sprintf("  end_date = %q\n", endDate)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "dates_test" {
  name      = %q
  operation = "database_backup"
  run_at    = "0 9 * * sat"
  database_backup_params = {
    scope = "system"
  }
%s%s}`, name, startLine, endLine)
}

// Test_CM_Scheduler_StartDateEndDateClear verifies that start_date and end_date
// can be set, cleared to "", removed from HCL (null semantics), and re-set.
func Test_CM_Scheduler_StartDateEndDateClear(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_Scheduler_StartDateEndDateClear: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	suffix := uuid.New().String()[:8]
	name := "tf-test-sched-dates-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: set both dates
			{
				Config: schedulerDatesConfig(name, "2026-08-01T00:00:00Z", "2027-08-01T00:00:00Z"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.dates_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.dates_test", "start_date", "2026-08-01T00:00:00Z"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.dates_test", "end_date", "2027-08-01T00:00:00Z"),
				),
			},
			// Step 2: clear both dates by setting to ""
			{
				Config: schedulerDatesConfig(name, "", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.dates_test", "start_date"),
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.dates_test", "end_date"),
				),
			},
			// Step 3: remove both dates from HCL (null-is-no-op — state becomes null)
			{
				Config: schedulerDatesConfig(name, "omit", "omit"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.dates_test", "start_date"),
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.dates_test", "end_date"),
				),
			},
			// Step 4: plan is stable after removing dates from HCL
			{
				Config:             schedulerDatesConfig(name, "omit", "omit"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 5: re-set start_date to verify the field can be set again
			{
				Config: schedulerDatesConfig(name, "2026-09-01T00:00:00Z", "omit"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_scheduler.dates_test", "start_date", "2026-09-01T00:00:00Z"),
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.dates_test", "end_date"),
				),
			},
		},
	})
}

// Test_CM_Scheduler_StartDateEndDateDrift verifies that an out-of-band change to
// start_date in CM is detected as drift on the next plan.
func Test_CM_Scheduler_StartDateEndDateDrift(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_Scheduler_StartDateEndDateDrift: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	suffix := uuid.New().String()[:8]
	name := "tf-test-sched-drift-" + suffix
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with start_date set
			{
				Config: schedulerDatesConfig(name, "2026-08-01T00:00:00Z", "omit"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.dates_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_scheduler.dates_test", "start_date", "2026-08-01T00:00:00Z"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_scheduler.dates_test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: change start_date out-of-band; next plan must detect drift
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — OOB drift step skipped")
						return
					}
					traceID := uuid.New().String()
					schedulerURL := common.URL_SCHEDULER_JOB_CONFIGS + "/" + capturedID
					payload := []byte(`{"start_date":"2026-10-01T00:00:00Z"}`)
					_, _ = client.UpdateData(context.Background(), traceID, schedulerURL, payload, "id")
				},
				Config:             schedulerDatesConfig(name, "2026-08-01T00:00:00Z", "omit"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_SchedulerList_DateAndAWSParams verifies that the ciphertrust_scheduler_list
// data source correctly handles absent dates (no zero-time) and that the
// cckm_key_rotation_params block uses flat aws_retain_alias (not nested aws_params).
func Test_CM_SchedulerList_DateAndAWSParams(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_SCHEDULER_ENABLED") == "" {
		t.Skip("skipping Test_CM_SchedulerList_DateAndAWSParams: set CIPHERTRUST_SCHEDULER_ENABLED=1 to enable")
	}
	suffix := uuid.New().String()[:8]
	name := "tf-test-schedlist-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_scheduler" "list_test" {
  name      = %q
  operation = "cckm_key_rotation"
  run_at    = "0 0 * * *"
  cckm_key_rotation_params = {
    cloud_name       = "aws"
    aws_retain_alias = true
  }
}

data "ciphertrust_scheduler_list" "all" {
  filters    = {}
  depends_on = [ciphertrust_scheduler.list_test]
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_scheduler.list_test", "id"),
					// Verify absent dates remain null (not zero-time "0001-01-01T00:00:00Z")
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.list_test", "start_date"),
					resource.TestCheckNoResourceAttr("ciphertrust_scheduler.list_test", "end_date"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
