.PHONY: build test test-race lint docker-build

VERSION ?= dev
IMAGE ?= ghcr.io/whereareiam/netbird-identity-gateway

build:
	go build -ldflags="-s -w -X main.version=$(VERSION)" -o bin/netbird-identity-gateway ./cmd/netbird-identity-gateway

test:
	go test -cover ./...

test-race:
	go test -race ./...

lint:
	gofmt -l -d .
	go vet ./...

docker-build:
	docker build --tag $(IMAGE):$(VERSION) .
