VGO=go # Set to vgo if building in Go 1.10
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

BINARY_NAME=ethsign
SRC_GOFILES := $(shell find . -name '*.go' -print)
.DELETE_ON_ERROR:

all: govulncheck build test
# govulncheck
GOVULNCHECK := $(GOBIN)/govulncheck
.PHONY: govulncheck
govulncheck: ${GOVULNCHECK}
	./govulnchecktool.sh
${GOVULNCHECK}:
	${VGO} install golang.org/x/vuln/cmd/govulncheck@latest
test: deps
		$(VGO) test  ./... -cover -coverprofile=coverage.txt -covermode=atomic
ethsign: ${SRC_GOFILES}
		$(VGO) build -o ${BINARY_NAME} -ldflags "-X main.buildDate=`date -u +\"%Y-%m-%dT%H:%M:%SZ\"` -X main.buildVersion=$(BUILD_VERSION)" -tags=prod -v
build: ethsign
clean: 
		$(VGO) clean
		rm -f ${BINARY_NAME}
deps:
		$(VGO) get
