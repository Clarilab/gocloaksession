all: vet test-all

test-all: test test-integration

test:
	go test -failfast -race -cover -v -run "^Integration" -coverprofile=coverage.out -covermode=atomic

test-integration:
	./run-tests.sh

vet:
	go vet ./...