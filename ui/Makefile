# Makefile for cr_viewer project

BINARY_NAME=bin/bhistory-ui

.PHONY: all clean deps build test

all: build

# Build the Go binary
build:
	# mkdir -f bin
	GOOS=linux go build -o $(BINARY_NAME)-linux main.go
	GOOS=darwin go build -o $(BINARY_NAME)-darwin main.go
	# GOOS=windows go build -o  $(BINARY_NAME)-windows.exe main.go

# Install dependencies
deps:
	go mod tidy

# Clean up build files
clean:
	rm -f $(BINARY_NAME)-linux $(BINARY_NAME)-darwin $(BINARY_NAME)-windows.exe
	rm -rf bin

# Run tests (if applicable)
fulltest:
	go test -v ./...

test:
	go test -v -run TestCrdFile ./...
