.PHONY: build test integration install

ZIG ?= zig
PREFIX ?= $(HOME)/.local

build:
	$(ZIG) build -Doptimize=ReleaseSafe

test:
	$(ZIG) build test

integration: build
	python3 tests/integration.py zig-out/bin/fella

install: build
	install -Dm755 zig-out/bin/fella "$(DESTDIR)$(PREFIX)/bin/fella"
