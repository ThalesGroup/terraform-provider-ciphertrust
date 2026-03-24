
default: fmt  install


build:
	go build -o terraform-provider-ciphertrust .

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
#TF_ACC=1 go test -v -cover -timeout 120m ./...
	TF_ACC=1 go test -v -timeout 120m ./internal/provider/ -run TestResourceGCPConnection

.PHONY: fmt lint test testacc build install generate
