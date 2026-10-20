
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
	#$(if $(TERRAFORM_BIN),TF_ACC_TERRAFORM_PATH=$(TERRAFORM_BIN) )TF_ACC= go test -v -cover -timeout=200s -parallel=10 ./...

JUNIT_FILE ?=

testacc:
#TF_ACC=1 gotestsum $(if $(JUNIT_FILE),--junitfile $(JUNIT_FILE)) --format testdox -- -v -cover -timeout 120m ./...
	rm -rf /work/ctp.log
	rm -rf /work/tf.log
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzure
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run Test_CM_CckmSchedulers
	TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureKeyNative$
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureAclUsersAndGroups
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureAclOOB
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureDataSourceVaultList
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureCertificate
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureCertificateValidation
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureCertificateMaxConfigAndRecover
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureCertificateNativeMinConfigAndRestore
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureCertificateNativeECConfigAndImport
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureCertificateUploadLocal
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureDataSourceCertificateList
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureKey
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureDataSourceKeyList
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureCertificateWithIssuer
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureSecret
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureSecretMaxConfigAndRecover
#TF_ACC=1 go test -v -timeout=120m ./internal/provider -run TestCckmAzureDataSourceSecretList

me: build
	rm -rf /work/ctp.log
	rm -rf /work/tf.log
	mkdir -p ~/.terraform.d/plugins/thales.com/terraform/ciphertrust/1.0.1/linux_amd64
	cp ./terraform-provider-ciphertrust ~/.terraform.d/plugins/thales.com/terraform/ciphertrust/1.0.1/linux_amd64
#	mkdir -p ~/.terraform.d/plugins/registry.terraform.io/thalesgroup/ciphertrust/1.1.0/linux_amd64
#	cp ./terraform-provider-ciphertrust ~/.terraform.d/plugins/registry.terraform.io/thalesgroup/ciphertrust/1.1.0/linux_amd64/terraform-provider-ciphertrust_v1.1.0

.PHONY: fmt lint test testacc build install generate docs

