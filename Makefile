VGO=go # Set to vgo if building in Go 1.10
BINARY_NAME=ethsign
SRC_GOFILES := $(shell find . -name '*.go' -print)
.DELETE_ON_ERROR:

all: build test
test: deps
		$(VGO) test  ./... -cover -coverprofile=coverage.txt -covermode=atomic
ethsign: ${SRC_GOFILES}
		$(VGO) build -o ${BINARY_NAME} -ldflags "-X main.buildDate=`date -u +\"%Y-%m-%dT%H:%M:%SZ\"` -X main.buildVersion=$(BUILD_VERSION)" -tags=prod -v
build: ethsign
clean: 
		$(VGO) clean
		rm -f ethsign
deps:
		$(VGO) get
