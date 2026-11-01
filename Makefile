# vpn - developer entry points.
#
# Works with GNU make (WSL2, Linux, macOS) and with the make that ships in
# w64devkit/MinGW on Windows. All targets are non-interactive and CI-safe.
#
#   make configure    configure the build tree (CMake preset: default)
#   make build        compile vpnd + unit tests
#   make test         run the unit test suite
#   make check        build with warnings-as-errors + run all tests
#   make fmt          clang-format the C++ sources in place
#   make fmt-check    fail if formatting differs (CI gate)
#   make lint         run clang-tidy over the compiled database
#   make dev          start postgres + redis + vpnd via compose
#   make dev-down     stop and remove the compose stack
#   make clean        remove the build tree

BUILD_DIR     ?= build
PRESET        ?= default
CMAKE         ?= cmake
CTEST         ?= ctest
JOBS          ?= 8
COMPOSE_FILE  ?= deploy/compose/compose.yaml

ifeq ($(OS),Windows_NT)
  SHELL := cmd.exe
  .SHELLFLAGS := /C
  RM := rmdir /s /q
  EXE := .exe
else
  RM := rm -rf
  EXE :=
endif

.PHONY: all configure build test check fmt fmt-check lint dev dev-down seed \
        demo-m1 clean help

all: build

configure:
	$(CMAKE) --preset $(PRESET)

build: configure
	$(CMAKE) --build --preset $(PRESET) --parallel $(JOBS)

test: build
	$(CTEST) --preset $(PRESET)

check:
	$(CMAKE) --preset default -DVPN_WARNINGS_AS_ERRORS=ON
	$(CMAKE) --build --preset default --parallel $(JOBS)
	$(CTEST) --preset default --output-on-failure

fmt:
	$(CMAKE) --build --preset $(PRESET) --target format

fmt-check:
	$(CMAKE) --build --preset $(PRESET) --target format-check

lint:
	$(CMAKE) --build --preset $(PRESET) --target lint

dev:
	docker compose -f $(COMPOSE_FILE) up --build -d
	@echo "vpnd:     http://127.0.0.1:8080/healthz"
	@echo "metrics:  http://127.0.0.1:9100/metrics"

dev-down:
	docker compose -f $(COMPOSE_FILE) down -v

seed:
	sh scripts/seed.sh

demo-m1:
	sh scripts/demo/m1.sh

clean:
	-$(RM) $(BUILD_DIR)

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) || true
