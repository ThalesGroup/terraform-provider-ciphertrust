
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
	@tfplugindocs generate --provider-dir . -provider-name terraform-provider-ciphertrust 2>&1 | grep -v "^rendering\|^exporting\|^compiling\|^using\|^running\|^getting\|^generating\|^cleaning\|^removing" || true
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

JUNIT_FILE ?=

testacc:
	TF_ACC=1 gotestsum $(if $(JUNIT_FILE),--junitfile $(JUNIT_FILE)) --format testdox -- -v -cover -timeout 120m ./...

.PHONY: fmt lint test testacc build install generate docs
