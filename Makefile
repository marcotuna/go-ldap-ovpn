.PHONY: ui-deps clean cleanall ci server server-mac server-linux server-win server-linux-package watch-server ui

PACKAGE_FOLDER = ldap_ovpn

DIST_ROOT=build
DIST_PATH=server
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

LDFLAGS += -X "ldap_ovpn/model.Version=$(VERSION)"
LDFLAGS += -X "ldap_ovpn/model.BuildNumber=$(BUILD_NUMBER)"
LDFLAGS += -X "ldap_ovpn/model.BuildDate=$(BUILD_DATE)"
LDFLAGS += -X "ldap_ovpn/model.BuildHash=$(BUILD_HASH)"

export GO111MODULE=on
export CGO_ENABLED=0
export PATH:=$(PWD)/$(BIN_DIR):$(PATH)

all: ui-deps ui server

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

server:
	go build -ldflags '$(LDFLAGS)' -o ./bin/ldap_ovpn ./cmd/ldap_ovpn/main.go

deps:
	go mod download

fmt:
	go fmt ./...

mac:
	mkdir -p bin/mac
	$(eval LDFLAGS += -X "ldap_ovpn/model.Edition=mac")
	env GOOS=darwin GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o ./bin/mac/ldap_ovpn ./cmd/ldap_ovpn/main.go

linux:
	mkdir -p bin/linux
	$(eval LDFLAGS += -X "ldap_ovpn/model.Edition=linux")
	env GOOS=linux GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o ./bin/linux/ldap_ovpn ./cmd/ldap_ovpn/main.go

win:
	$(eval LDFLAGS += -X "ldap_ovpn/model.Edition=win")
	env GOOS=windows GOARCH=amd64 go build -ldflags '$(LDFLAGS)' -o ./bin/win/ldap_ovpn.exe ./cmd/ldap_ovpn/main.go

lint: check-lint
	golangci-lint run ./...

lint-diff: check-lint
	golangci-lint run ./... --out-format tab --new-from-rev=HEAD~1

lint-checkstyle: check-lint
	golangci-lint --out-format checkstyle run ./...

test:
	go test -v ./...

doc:
	go doc ./...

clean:
	rm -rf bin