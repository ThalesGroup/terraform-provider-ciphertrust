
default: fmt  install


build:
	go build -v ./...

install: build
	go install -v ./...

lint:
	golangci-lint run

generate:
	cd tools; go generate ./...

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -timeout=120s -parallel=10 ./...

testacc:
	rm -rf ctp.log
#TF_ACC=1 go test -v -cover -timeout 120m ./...
#TF_ACC=1 go test -v -timeout 120m ./internal/provider/ -run TestCckm
#TF_ACC=1 go test -v -timeout 120m ./internal/provider/ -run TestCckmSchedulers
#TF_ACC=1 go test -v -timeout 120m ./internal/provider/ -run TestCckmAwsKeyNative
#TF_ACC=1 go test -v -timeout 120m ./internal/provider/ -run TestCckmAwsImportKeys
	TF_ACC=1 go test -v -timeout 120m ./internal/provider/ -run TestCckmAwsKeyMultiRegion
#TF_ACC=1 go test -v -timeout 120m ./internal/provider/ -run TestCckmAwsKeyImport

.PHONY: fmt lint test testacc build install generate

me:
	rm -rf ctp.log
	go build -o ./terraform-provider-ciphertrust
	cp terraform-provider-ciphertrust ~/.terraform.d/plugins/thales.com/terraform/ciphertrust/1.0.1/linux_amd64/
