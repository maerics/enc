test: fmt vet
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

BUILD_VERSION = $(shell git describe --exact-match --tags)
BUILD_COMMIT = $(shell git rev-parse head)
BUILD_TIMESTAMP = $(shell date -z zulu +'%Y-%m-%dT%H:%M:%SZ')
build: test
	go build \
		-ldflags " \
			-X 'main.version=$(BUILD_VERSION)' \
			-X 'main.commit=$(BUILD_COMMIT)' \
			-X 'main.date=$(BUILD_TIMESTAMP)' \
		" \
	-o ./enc *.go

release-check: test
	goreleaser check

local-release: release-check clean
	goreleaser release --snapshot --clean

ensure-no-local-changes:
	@if [ "$(shell git status -s)" != "" ]; then \
		git status -s; \
		echo "\nFATAL: refusing to release with local changes; see git status."; \
		exit 1; \
	fi

release: ensure-no-local-changes clean
	goreleaser release

clean:
	rm -rf ./enc ./dist
