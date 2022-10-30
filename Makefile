.PHONY: clean bin mac linux win

PACKAGE_FOLDER = go-ldap-ovpn

BIN_DIR=bin

# Build Flags
VERSION ?= $(VERSION:)
BUILD_NUMBER ?= $(BUILD_NUMBER:)
BUILD_DATE = $(shell date -u)
BUILD_HASH = $(shell git rev-parse HEAD)

# If we don't set the build number it defaults to dev
ifeq ($(VERSION),)
	VERSION := 0.0.0
endif

# If we don't set the build number it defaults to dev
ifeq ($(BUILD_NUMBER),)
	BUILD_NUMBER := dev
endif

LDFLAGS += -X "go-ldap-ovpn/model.Version=$(VERSION)"
LDFLAGS += -X "go-ldap-ovpn/model.BuildNumber=$(BUILD_NUMBER)"
LDFLAGS += -X "go-ldap-ovpn/model.BuildDate=$(BUILD_DATE)"
LDFLAGS += -X "go-ldap-ovpn/model.BuildHash=$(BUILD_HASH)"

export GO111MODULE=on
export CGO_ENABLED=0
export PATH:=$(PWD)/$(BIN_DIR):$(PATH)

all: bin

check-lint:
	@if ! [ -x "$$(command -v golangci-lint)" ]; then \
		echo "Downloading golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi;

modd:
	@if ! [ -x "$$(command -v modd)" ]; then \
		echo "Downloading modd..."; \
		go install github.com/cortesi/modd/cmd/modd@latest; \
	fi;

bin:
	go build -ldflags '$(LDFLAGS)' -o ./bin/go-ldap-ovpn ./cmd/go-ldap-ovpn/main.go

deps:
	go mod download

fmt:
	go fmt ./...

mac:
	mkdir -p bin/mac
	$(eval LDFLAGS += -X "go-ldap-ovpn/model.Edition=mac")
	env GOOS=darwin GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o ./bin/mac/go-ldap-ovpn ./cmd/go-ldap-ovpn/main.go

linux:
	mkdir -p bin/linux
	$(eval LDFLAGS += -X "go-ldap-ovpn/model.Edition=linux")
	env GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o ./bin/linux/go-ldap-ovpn ./cmd/go-ldap-ovpn/main.go

win:
	$(eval LDFLAGS += -X "go-ldap-ovpn/model.Edition=win")
	env GOOS=windows GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o ./bin/win/go-ldap-ovpn.exe ./cmd/go-ldap-ovpn/main.go

lint: check-lint
	golangci-lint run ./...

lint-diff: check-lint
	golangci-lint run ./... --out-format tab --new-from-rev=HEAD~1

lint-checkstyle: check-lint
	golangci-lint --out-format checkstyle run ./...

test:
	go test -v ./...

clean:
	rm -rf bin