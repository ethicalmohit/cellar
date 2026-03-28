BINARY   := cellar
PREFIX   ?= /usr/local
BINDIR   := $(PREFIX)/bin
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -ldflags "-X main.version=$(VERSION)"

.PHONY: build install uninstall clean run

build:
	go build $(LDFLAGS) -o $(BINARY) .

install: build
	install -d $(BINDIR)
	install -m 755 $(BINARY) $(BINDIR)/$(BINARY)
	@echo "Installed to $(BINDIR)/$(BINARY)"

uninstall:
	rm -f $(BINDIR)/$(BINARY)
	@echo "Removed $(BINDIR)/$(BINARY)"

clean:
	rm -f $(BINARY)

run:
	go run .
