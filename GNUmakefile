
default: fmt  install


build:
	go build -v ./...

buildme:
	go build -o ./terraform-provider-ciphertrust
	mkdir -p ~/.terraform.d/plugins/thales.com/terraform/ciphertrust/1.0.1/linux_amd64/
	cp terraform-provider-ciphertrust ~/.terraform.d/plugins/thales.com/terraform/ciphertrust/1.0.1/linux_amd64/

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
	TF_ACC=1 go test -v -cover -timeout 120m ./...

.PHONY: fmt lint test testacc build install generate
