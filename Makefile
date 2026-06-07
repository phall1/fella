.PHONY: all build test install uninstall clean validate validate-all

ZIG ?= zig
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= /var/lib/fella

all: build

build:
	$(ZIG) build

test:
	$(ZIG) build test

install: build
	@echo "[+] Installing fella to $(BINDIR)"
	install -Dm755 zig-out/bin/fella $(BINDIR)/fella
	install -d $(LIBDIR)
	install -d $(LIBDIR)/original
	@echo "[+] fella installed. Run: sudo fella init"

uninstall:
	@echo "[-] Removing fella from $(BINDIR)"
	rm -f $(BINDIR)/fella
	@echo "[!] Session data in $(LIBDIR) was NOT removed. Run 'sudo fella wipe' or 'rm -rf $(LIBDIR)' manually."

clean:
	$(ZIG) build clean 2>/dev/null || rm -rf .zig-cache zig-out

validate: build
	sudo ./scripts/validate.sh --integration

validate-all: build
	sudo ./scripts/validate.sh --all
