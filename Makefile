# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

GO_CMD?=go
DOCKER_CMD?=docker

TEST?=$$($(GO_CMD) list ./... github.com/openbao/openbao/api/v2/... github.com/openbao/openbao/sdk/v2/... | grep -v /vendor/ | grep -v /integ)
TEST_TIMEOUT?=45m
EXTENDED_TEST_TIMEOUT=60m
INTEG_TEST_TIMEOUT=120m
VETARGS?=-asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr
GOFMT_FILES?=$$(find . -name '*.go' | grep -v pb.go | grep -v vendor)
SED?=$(shell command -v gsed || command -v sed)

GO_VERSION_MIN=$$(cat $(CURDIR)/.go-version)
PROTOC_VERSION_MIN=3.21.12
CGO_ENABLED?=0
ifneq ($(FDB_ENABLED), )
	CGO_ENABLED=1
	BUILD_TAGS+=foundationdb
endif

default: dev

# bin generates the releasable binaries for OpenBao
bin: prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS) ui' sh -c "'$(CURDIR)/scripts/build.sh'"

# dev creates binaries for testing OpenBao locally. These are put
# into ./bin/ as well as $GOPATH/bin
dev: BUILD_TAGS+=testonly
dev: prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' OPENBAO_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
dev-ui: BUILD_TAGS+=testonly
dev-ui: assetcheck prep
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS) ui' OPENBAO_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"
dev-dynamic: BUILD_TAGS+=testonly
dev-dynamic: prep
	@CGO_ENABLED=1 BUILD_TAGS='$(BUILD_TAGS)' OPENBAO_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

# *-mem variants will enable memory profiling which will write snapshots of heap usage
# to $TMP/vaultprof every 5 minutes. These can be analyzed using `$ go tool pprof <profile_file>`.
# Note that any build can have profiling added via: `$ BUILD_TAGS=memprofiler make ...`
dev-mem: BUILD_TAGS+=memprofiler
dev-mem: dev
dev-ui-mem: BUILD_TAGS+=memprofiler
dev-ui-mem: assetcheck dev-ui
dev-dynamic-mem: BUILD_TAGS+=memprofiler
dev-dynamic-mem: dev-dynamic

# Creates a Docker image by adding the compiled linux/amd64 binary found in ./bin.
# The resulting image is tagged "openbao:dev".
docker-dev: BUILD_TAGS+=testonly
docker-dev: prep
	$(DOCKER_CMD) build --build-arg VERSION=$(GO_VERSION_MIN) --build-arg BUILD_TAGS="$(BUILD_TAGS)" -f scripts/docker/Dockerfile -t openbao:dev .

docker-dev-ui: BUILD_TAGS+=testonly
docker-dev-ui: prep
	$(DOCKER_CMD) build --build-arg VERSION=$(GO_VERSION_MIN) --build-arg BUILD_TAGS="$(BUILD_TAGS)" -f scripts/docker/Dockerfile.ui -t openbao:dev-ui .

# test runs the unit tests and vets the code
test: BUILD_TAGS+=testonly
test: prep
	@CGO_ENABLED=$(CGO_ENABLED) \
	BAO_ADDR= \
	BAO_TOKEN= \
	BAO_DEV_ROOT_TOKEN_ID= \
	BAO_ACC= \
	$(GO_CMD) test -tags='$(BUILD_TAGS)' $(TEST) $(TESTARGS) -timeout=$(TEST_TIMEOUT) -parallel=20

testcompile: BUILD_TAGS+=testonly
testcompile: prep
	@for pkg in $(TEST) ; do \
		$(GO_CMD) test -v -c -tags='$(BUILD_TAGS)' $$pkg -parallel=4 ; \
	done

# testacc runs acceptance tests
testacc: BUILD_TAGS+=testonly
testacc: prep
	@if [ "$(TEST)" = "./..." ]; then \
		echo "ERROR: Set TEST to a specific package"; \
		exit 1; \
	fi
	BAO_ACC=1 $(GO_CMD) test -tags='$(BUILD_TAGS)' $(TEST) -v $(TESTARGS) -timeout=$(EXTENDED_TEST_TIMEOUT)

# testrace runs the race checker
testrace: BUILD_TAGS+=testonly
testrace: prep
	@CGO_ENABLED=1 \
	BAO_ADDR= \
	BAO_TOKEN= \
	BAO_DEV_ROOT_TOKEN_ID= \
	BAO_ACC= \
	$(GO_CMD) test -tags='$(BUILD_TAGS)' -race $(TEST) $(TESTARGS) -timeout=$(EXTENDED_TEST_TIMEOUT) -parallel=20

cover:
	./scripts/coverage.sh --html

# vet runs the Go source code static analysis tool `vet` to find
# any common errors.
vet:
	@$(GO_CMD) list -f '{{.Dir}}' ./... | grep -v /vendor/ \
		| grep -v '.*github.com/hashicorp/vault$$' \
		| xargs $(GO_CMD) vet ; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Vet found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi
	@$(GO_CMD) list -f '{{.Dir}}' github.com/openbao/openbao/api/v2/... | grep -v /vendor/ \
		| grep -v '.*github.com/hashicorp/vault$$' \
		| xargs $(GO_CMD) vet ; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Vet found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi
	@$(GO_CMD) list -f '{{.Dir}}' github.com/openbao/openbao/sdk/v2/... | grep -v /vendor/ \
		| grep -v '.*github.com/hashicorp/vault$$' \
		| xargs $(GO_CMD) vet ; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Vet found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi

# deprecations runs staticcheck tool to look for deprecations. Checks entire code to see if it
# has deprecated function, variable, constant or field
deprecations: bootstrap prep
	@BUILD_TAGS='$(BUILD_TAGS)' ./scripts/deprecations-checker.sh ""

# ci-deprecations runs staticcheck tool to look for deprecations. All output gets piped to revgrep
# which will only return an error if changes that is not on main has deprecated function, variable, constant or field
ci-deprecations: ci-bootstrap prep
	@BUILD_TAGS='$(BUILD_TAGS)' ./scripts/deprecations-checker.sh main

tools/codechecker/.bin/codechecker:
	@cd tools/codechecker && $(GO_CMD) build -o .bin/codechecker .

# vet-codechecker runs our custom linters on the test functions. All output gets
# piped to revgrep which will only return an error if new piece of code violates
# the check
vet-codechecker: bootstrap tools/codechecker/.bin/codechecker prep
	@$(GO_CMD) vet -vettool=./tools/codechecker/.bin/codechecker -tags=$(BUILD_TAGS) ./... 2>&1 | go run github.com/golangci/revgrep/cmd/revgrep@latest
	@$(GO_CMD) vet -vettool=./tools/codechecker/.bin/codechecker -tags=$(BUILD_TAGS) github.com/openbao/openbao/api/v2/... 2>&1 | go run github.com/golangci/revgrep/cmd/revgrep@latest
	@$(GO_CMD) vet -vettool=./tools/codechecker/.bin/codechecker -tags=$(BUILD_TAGS) github.com/openbao/openbao/sdk/v2/... 2>&1 | go run github.com/golangci/revgrep/cmd/revgrep@latest

# vet-codechecker runs our custom linters on the test functions. All output gets
# piped to revgrep which will only return an error if new piece of code that is
# not on main violates the check
ci-vet-codechecker: ci-bootstrap tools/codechecker/.bin/codechecker prep
	@$(GO_CMD) vet -vettool=./tools/codechecker/.bin/codechecker -tags=$(BUILD_TAGS) ./... 2>&1 | go run github.com/golangci/revgrep/cmd/revgrep@latest origin/main
	@$(GO_CMD) vet -vettool=./tools/codechecker/.bin/codechecker -tags=$(BUILD_TAGS) github.com/openbao/openbao/api/v2/... 2>&1 | go run github.com/golangci/revgrep/cmd/revgrep@latest origin/main
	@$(GO_CMD) vet -vettool=./tools/codechecker/.bin/codechecker -tags=$(BUILD_TAGS) github.com/openbao/openbao/sdk/v2/... 2>&1 | go run github.com/golangci/revgrep/cmd/revgrep@latest origin/main

# lint runs vet plus a number of other checkers, it is more comprehensive, but louder
lint:
	@$(GO_CMD) list -f '{{.Dir}}' ./... | grep -v /vendor/ \
		| xargs golangci-lint run --timeout 10m; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Lint found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi
	@$(GO_CMD) list -f '{{.Dir}}' github.com/openbao/openbao/api/v2/... | grep -v /vendor/ \
		| xargs golangci-lint run --timeout 10m; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Lint found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi
	@$(GO_CMD) list -f '{{.Dir}}' github.com/openbao/openbao/sdk/v2/... | grep -v /vendor/ \
		| xargs golangci-lint run --timeout 10m; if [ $$? -eq 1 ]; then \
			echo ""; \
			echo "Lint found suspicious constructs. Please check the reported constructs"; \
			echo "and fix them if necessary before submitting the code for reviewal."; \
		fi

# for ci jobs, runs lint against the changed packages in the commit
ci-lint:
	@golangci-lint run --timeout 10m --new-from-rev=HEAD~

# prep runs `go generate` to build the dynamically generated
# source files.
#
# n.b.: prep used to depend on fmtcheck, but since fmtcheck is
# now run as a pre-commit hook (and there's little value in
# making every build run the formatter), we've removed that
# dependency.
prep:
	@sh -c "'$(CURDIR)/scripts/goversioncheck.sh' '$(GO_VERSION_MIN)'"
	@GOARCH= GOOS= $(GO_CMD) generate $$($(GO_CMD) list ./... | grep -v /vendor/)
	@GOARCH= GOOS= $(GO_CMD) generate $$($(GO_CMD) list github.com/openbao/openbao/api/v2/... | grep -v /vendor/)
	@GOARCH= GOOS= $(GO_CMD) generate $$($(GO_CMD) list github.com/openbao/openbao/sdk/v2/... | grep -v /vendor/)
	@if [ -d .git/hooks ]; then cp .hooks/* .git/hooks/; fi

# bootstrap the build by downloading additional tools that may be used by devs
bootstrap: ci-bootstrap
	go generate -tags tools tools/tools.go

# Note: if you have plugins in GOPATH you can update all of them via something like:
# for i in $(ls | grep openbao-plugin-); do cd $i; git remote update; git reset --hard origin/master; dep ensure -update; git add .; git commit; git push; cd ..; done
update-plugins:
	grep openbao-plugin- go.mod | cut -d ' ' -f 1 | while read -r P; do echo "Updating $P..."; go get -v "$P"; done

static-assets-dir:
	@mkdir -p ./http/web_ui

install-ui-dependencies:
	@echo "--> Installing JavaScript assets"
	@cd ui && yarn

test-ember: install-ui-dependencies
	@echo "--> Running ember tests"
	@cd ui && yarn run test:oss

test-ember-enos: install-ui-dependencies
	@echo "--> Running ember tests with a real backend"
	@cd ui && yarn run test:enos

check-openbao-in-path:
	@OPENBAO_BIN=$$(command -v bao) || { echo "bao command not found"; exit 1; }; \
		[ -x "$$OPENBAO_BIN" ] || { echo "$$OPENBAO_BIN not executable"; exit 1; }; \
		printf "Using OpenBao at %s:\n\$$ openbao version\n%s\n" "$$OPENBAO_BIN" "$$(bao version)"

ember-dist: install-ui-dependencies
	@cd ui && npm rebuild node-sass
	@echo "--> Building Ember application"
	@cd ui && yarn run build
	@rm -rf ui/if-you-need-to-delete-this-open-an-issue-async-disk-cache

ember-dist-dev: install-ui-dependencies
	@cd ui && npm rebuild node-sass
	@echo "--> Building Ember application"
	@cd ui && yarn run build:dev

static-dist: ember-dist
static-dist-dev: ember-dist-dev

proto: bootstrap
	@sh -c "'$(CURDIR)/scripts/protocversioncheck.sh' '$(PROTOC_VERSION_MIN)'"
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative builtin/logical/kv/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative vault/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative helper/storagepacker/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative helper/forwarding/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/logical/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative physical/raft/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative helper/identity/mfa/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative helper/identity/types.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/database/dbplugin/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/database/dbplugin/v5/proto/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/plugin/pb/*.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative vault/tokens/token.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative sdk/helper/pluginutil/*.proto

	# No additional sed expressions should be added to this list. Going forward
	# we should just use the variable names chosen by protobuf. These are left
	# here for backwards compatibility, namely for SDK compilation.
	$(SED) -i -e 's/Id/ID/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' vault/request_forwarding_service.pb.go
	$(SED) -i -e 's/Idp/IDP/' -e 's/Url/URL/' -e 's/Id/ID/' -e 's/IDentity/Identity/' -e 's/EntityId/EntityID/' -e 's/Api/API/' -e 's/Qr/QR/' -e 's/Totp/TOTP/' -e 's/Mfa/MFA/' -e 's/Pingid/PingID/' -e 's/namespaceId/namespaceID/' -e 's/Ttl/TTL/' -e 's/BoundCidrs/BoundCIDRs/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' helper/identity/types.pb.go helper/identity/mfa/types.pb.go helper/storagepacker/types.pb.go sdk/plugin/pb/backend.pb.go sdk/logical/identity.pb.go

	# This will inject the sentinel struct tags as decorated in the proto files.
	protoc-go-inject-tag -input=./helper/identity/types.pb.go
	protoc-go-inject-tag -input=./helper/identity/mfa/types.pb.go

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

fmt: ci-bootstrap
	find . -name '*.go' | grep -v pb.go | grep -v vendor | xargs go run mvdan.cc/gofumpt@latest -w

semgrep:
	semgrep --include '*.go' --exclude 'vendor' -a -f tools/semgrep .

semgrep-ci:
	semgrep --error --include '*.go' --exclude 'vendor' -f tools/semgrep/ci .

docker-semgrep:
	$(DOCKER_CMD) run --rm --mount "type=bind,source=$(PWD),destination=/src,chown=true,relabel=shared" docker.io/returntocorp/semgrep:latest semgrep --include '*.go' --exclude 'vendor' -a -f tools/semgrep .

docker-semgrep-ci:
	$(DOCKER_CMD) run --rm --mount "type=bind,source=$(PWD),destination=/src,chown=true,relabel=shared" docker.io/returntocorp/semgrep:latest semgrep --error --include '*.go' --exclude 'vendor' -a -f tools/semgrep/ci .

assetcheck:
	@echo "==> Checking compiled UI assets..."
	@sh -c "'$(CURDIR)/scripts/assetcheck.sh'"

spellcheck:
	@echo "==> Spell checking website..."
	$(GO_CMD) run github.com/client9/misspell/cmd/misspell@latest -error -source=text website/source

mysql-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/mysql-database-plugin ./plugins/database/mysql/mysql-database-plugin

mysql-legacy-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/mysql-legacy-database-plugin ./plugins/database/mysql/mysql-legacy-database-plugin

cassandra-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/cassandra-database-plugin ./plugins/database/cassandra/cassandra-database-plugin

influxdb-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/influxdb-database-plugin ./plugins/database/influxdb/influxdb-database-plugin

postgresql-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/postgresql-database-plugin ./plugins/database/postgresql/postgresql-database-plugin

mssql-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/mssql-database-plugin ./plugins/database/mssql/mssql-database-plugin

hana-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/hana-database-plugin ./plugins/database/hana/hana-database-plugin

mongodb-database-plugin:
	@CGO_ENABLED=0 $(GO_CMD) build -o bin/mongodb-database-plugin ./plugins/database/mongodb/mongodb-database-plugin

.PHONY: bin default prep test vet bootstrap ci-bootstrap fmt fmtcheck mysql-database-plugin mysql-legacy-database-plugin cassandra-database-plugin influxdb-database-plugin postgresql-database-plugin mssql-database-plugin hana-database-plugin mongodb-database-plugin ember-dist ember-dist-dev static-dist static-dist-dev assetcheck check-openbao-in-path packages build build-ci semgrep semgrep-ci vet-godoctests ci-vet-godoctests

.NOTPARALLEL: ember-dist ember-dist-dev

.PHONY: openapi
openapi: dev
	@$(CURDIR)/scripts/gen_openapi.sh

.PHONY: vulncheck
vulncheck:
	$(GO_CMD) run golang.org/x/vuln/cmd/govulncheck@latest -show verbose ./...
	$(GO_CMD) run golang.org/x/vuln/cmd/govulncheck@latest -show verbose github.com/openbao/openbao/api/v2/...
	$(GO_CMD) run golang.org/x/vuln/cmd/govulncheck@latest -show verbose github.com/openbao/openbao/sdk/v2/...

.PHONY: tidy-all
tidy-all:
	cd api && $(GO_CMD) mod tidy
	cd api/auth/approle && $(GO_CMD) mod tidy
	cd api/auth/kubernetes && $(GO_CMD) mod tidy
	cd api/auth/ldap && $(GO_CMD) mod tidy
	cd api/auth/userpass && $(GO_CMD) mod tidy
	cd sdk && $(GO_CMD) mod tidy
	$(GO_CMD) mod tidy

.PHONY: ci-tidy-all
ci-tidy-all:
	git diff --quiet
	cd api && $(GO_CMD) mod tidy
	cd api/auth/approle && $(GO_CMD) mod tidy
	cd api/auth/kubernetes && $(GO_CMD) mod tidy
	cd api/auth/ldap && $(GO_CMD) mod tidy
	cd api/auth/userpass && $(GO_CMD) mod tidy
	cd sdk && $(GO_CMD) mod tidy
	$(GO_CMD) mod tidy
	git diff --quiet || (echo -e "\n\nModified files:" && git status --short && echo -e "\n\nRun 'make tidy-all' locally and commit the changes.\n" && exit 1)

.PHONY: release-changelog
release-changelog: $(wildcard changelog/*.txt)
	@:$(if $(LAST_RELEASE),,$(error please set the LAST_RELEASE environment variable for changelog generation))
	@:$(if $(THIS_RELEASE),,$(error please set the THIS_RELEASE environment variable for changelog generation))
	changelog-build -changelog-template changelog/changelog.tmpl -entries-dir changelog -git-dir . -note-template changelog/note.tmpl -last-release $(LAST_RELEASE) -this-release $(THIS_RELEASE)
