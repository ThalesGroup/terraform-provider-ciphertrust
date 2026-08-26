
default: fmt  install


build:
	go build -o terraform-provider-ciphertrust .

install: build
	go install -v ./...

lint:
	golangci-lint run

generate:
	cd tools; go generate ./...

docs:
	@echo "Generating docs..."
	@cp docs/index.md /tmp/ciphertrust-docs-index.md.bak
	@tfplugindocs generate --provider-dir . -provider-name terraform-provider-ciphertrust 2>&1 | grep -v "^rendering\|^exporting\|^compiling\|^using\|^running\|^getting\|^generating\|^cleaning\|^removing" || true
	@cp /tmp/ciphertrust-docs-index.md.bak docs/index.md
	@rm -f /tmp/ciphertrust-docs-index.md.bak
	@CHANGED=$$(git diff --name-only docs/ 2>/dev/null); \
	NEW=$$(git ls-files --others --exclude-standard docs/ 2>/dev/null); \
	ALL=$$(printf '%s\n' $$CHANGED $$NEW | grep .); \
	if [ -z "$$ALL" ]; then \
		echo "Docs are already up to date."; \
	else \
		COUNT=$$(printf '%s\n' $$ALL | wc -l | tr -d ' '); \
		echo "Updated docs ($$COUNT file(s) changed):"; \
		printf '%s\n' $$ALL | sed 's/^/  - /'; \
		echo "Successfully updated docs."; \
	fi

fmt:
	gofmt -s -w -e .

test:
	$(if $(TERRAFORM_BIN),TF_ACC_TERRAFORM_PATH=$(TERRAFORM_BIN) )TF_ACC= go test -v -cover -timeout=200s -parallel=10 ./...

# Tests excluded from `make unit` because they are not hermetic. Both groups are
# still run by `make test` / `make testacc`.
#
#   TestUnit_Provider_SettingsHonoured_* , _Cluster_IsClusteredTrue and
#   _Precedence_BlockOverridesEnv call the provider's Configure, which
#   authenticates against a live CipherTrust Manager and fetches /system/info.
#   Despite the TestUnit_ prefix they are integration tests.
#
#   TestRoundTrip_ConcurrentRequests_NoRace mocks the auth endpoint with
#   httptest but forwards the outer request to https://example.com, so it
#   needs outbound internet access.
NON_HERMETIC_TESTS = TestUnit_Provider_SettingsHonoured_ProviderBlock|TestUnit_Provider_SettingsHonoured_EnvVars|TestUnit_Provider_SettingsHonoured_ConfigFile|TestUnit_Provider_Cluster_IsClusteredTrue|TestUnit_Provider_Precedence_BlockOverridesEnv|TestRoundTrip_ConcurrentRequests_NoRace

# Everything that passes with no CipherTrust Manager and no network. Acceptance
# tests skip themselves because TF_ACC is empty; plan-only resource.UnitTest
# cases still run, so a terraform binary must be on PATH.
unit:
	$(if $(TERRAFORM_BIN),TF_ACC_TERRAFORM_PATH=$(TERRAFORM_BIN) )TF_ACC= go test -timeout=300s -parallel=10 -skip '$(NON_HERMETIC_TESTS)' ./...

JUNIT_FILE ?=

testacc:
	TF_ACC=1 gotestsum $(if $(JUNIT_FILE),--junitfile $(JUNIT_FILE)) --format testdox -- -v -cover -timeout 120m ./...

.PHONY: fmt lint unit test testacc build install generate docs
