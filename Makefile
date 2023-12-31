build:
	go build -o bin/go-bank

run: build
	./bin/go-bank

test:
	@go test -v ./..

shortt:
	go test -short ./..

.PHONY: gen
gen: 
	mockgen -source=pkg/storage/storage.go \
	-destination=pkg/mocks/storage_mock.go

.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	rm coverage.out