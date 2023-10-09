build:
	go build -o bin/go-bank

run: build
	./bin/go-bank

test:
	@go test -v ./..

.PHONY: cover
cover:
	go test -short -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out
	rm coverage.out