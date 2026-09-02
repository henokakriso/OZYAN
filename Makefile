CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -Iinclude -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
LDFLAGS = -ldl -rdynamic
BUILD   = build
TARGET  = ozayn

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    PLATFORM_SRC = src/platform/linux/platform_linux.c src/platform/linux/platform_info_linux.c
    PLATFORM_NAME = linux
    LDFLAGS += -lX11 -lXtst -lasound
endif
ifeq ($(UNAME_S),Darwin)
    PLATFORM_SRC = src/platform/macos/platform_macos.c src/platform/macos/platform_info_macos.c
    PLATFORM_NAME = macos
    LDFLAGS += -framework CoreFoundation
endif
ifeq ($(findstring MINGW,$(UNAME_S)),MINGW)
    PLATFORM_SRC = src/platform/windows/platform_windows.c src/platform/windows/platform_info_windows.c
    PLATFORM_NAME = windows
    LDFLAGS += -lws2_32 -liphlpapi
    TARGET = ozayn.exe
endif
ifeq ($(findstring MSYS,$(UNAME_S)),MSYS)
    PLATFORM_SRC = src/platform/windows/platform_windows.c src/platform/windows/platform_info_windows.c
    PLATFORM_NAME = windows
    LDFLAGS += -lws2_32 -liphlpapi
    TARGET = ozayn.exe
endif

# Default to Linux if nothing matched
ifndef PLATFORM_SRC
    PLATFORM_SRC = src/platform/linux/platform_linux.c src/platform/linux/platform_info_linux.c
    PLATFORM_NAME = linux
endif

SRCS    = $(wildcard src/*.c) $(wildcard src/core/*.c) $(PLATFORM_SRC)
OBJS    = $(patsubst src/%.c, $(BUILD)/%.o, $(SRCS))

PLUGIN_DIR  = plugins
PLUGIN_SRCS = $(wildcard $(PLUGIN_DIR)/*.c)
PLUGIN_SO   = $(patsubst $(PLUGIN_DIR)/%.c, $(PLUGIN_DIR)/%.so, $(PLUGIN_SRCS))

TOOLS_DIR   = tools
TOOLS_SRCS  = $(wildcard $(TOOLS_DIR)/*.c)
TOOLS_BIN   = $(patsubst $(TOOLS_DIR)/%.c, $(BUILD)/%, $(TOOLS_SRCS))

# Test sources
TEST_MAIN   = tests/test_main.c
TEST_SRCS   = $(wildcard tests/unit/*.c) $(wildcard tests/integration/*.c) $(wildcard tests/system/*.c) $(wildcard tests/failure/*.c) $(wildcard tests/regression/*.c) $(wildcard 02_PLATFORM/tests/*.c)
TEST_ALL_SRCS = $(TEST_MAIN) $(TEST_SRCS)
TEST_BIN    = $(BUILD)/ozayn_test
TEST_OBJS   = $(filter-out build/main.o, $(OBJS))

all: $(BUILD)/$(TARGET) plugins tools

$(BUILD)/%.o: src/%.c | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo ""
	@echo "  Built: $(BUILD)/$(TARGET) ($(PLATFORM_NAME))"
	@echo ""

$(BUILD):
	mkdir -p $(BUILD)

plugins: $(PLUGIN_SO)

$(PLUGIN_DIR)/%.so: $(PLUGIN_DIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC $< -o $@
	@echo "  Built plugin: $@"

tools: $(TOOLS_BIN)

$(BUILD)/%: $(TOOLS_DIR)/%.c | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@
	@echo "  Built tool: $@"

run: all
	./$(BUILD)/$(TARGET)

test: all $(TEST_BIN)
	@echo ""
	@echo "  ======================================================"
	@echo "  Running OZAYN Core Test Suite..."
	@echo "  ======================================================"
	@echo ""
	@./$(TEST_BIN)

$(TEST_BIN): $(TEST_OBJS) $(TEST_ALL_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $(TEST_ALL_SRCS) $(TEST_OBJS) $(LDFLAGS) -o $@
	@echo "  Built test: $@"

clean:
	rm -rf $(BUILD)
	rm -f $(PLUGIN_DIR)/*.so
	rm -rf dist

# --- Release Engineering (Stage 30) ---

# Version injection via -D flags
VERSION_MAJOR = 0
VERSION_MINOR = 1
VERSION_PATCH = 0
BUILD_ID     := $(shell date +%Y%m%d.%H%M%S)
GIT_COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH   := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

RELEASE_CFLAGS = $(CFLAGS) \
    -DOZAYN_RELEASE_VERSION=\"$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)\" \
    -DOZAYN_RELEASE_BUILD_ID=\"$(BUILD_ID)\" \
    -DOZAYN_RELEASE_COMMIT=\"$(GIT_COMMIT)\" \
    -DOZAYN_RELEASE_BRANCH=\"$(GIT_BRANCH)\"

# Package target — create distribution tarball
package: all
	@mkdir -p dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)
	@cp $(BUILD)/$(TARGET) dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/
	@cp -r plugins/*.so dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/ 2>/dev/null || true
	@cp ozayn.conf dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/ 2>/dev/null || true
	@echo "# OZAYN Release Manifest" > dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/release.manifest
	@echo "version=$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)" >> dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/release.manifest
	@echo "build_id=$(BUILD_ID)" >> dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/release.manifest
	@echo "commit=$(GIT_COMMIT)" >> dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/release.manifest
	@echo "branch=$(GIT_BRANCH)" >> dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/release.manifest
	@cd dist && tar czf ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH).tar.gz ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)/
	@rm -rf dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)
	@echo ""
	@echo "  Package: dist/ozayn-$(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH).tar.gz"
	@echo ""

# Install target
PREFIX ?= /usr/local
install: all
	@install -d $(DESTDIR)$(PREFIX)/bin
	@install -d $(DESTDIR)$(PREFIX)/lib/ozayn
	@install -d $(DESTDIR)$(PREFIX)/share/ozayn
	@install -m 755 $(BUILD)/$(TARGET) $(DESTDIR)$(PREFIX)/bin/
	@cp -r plugins/*.so $(DESTDIR)$(PREFIX)/lib/ozayn/ 2>/dev/null || true
	@echo ""
	@echo "  Installed to $(DESTDIR)$(PREFIX)/"
	@echo ""

# Release — full release workflow: clean, build, test, package
release: clean all test package
	@echo ""
	@echo "  ======================================================"
	@echo "  RELEASE: $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_PATCH)"
	@echo "  Build:  $(BUILD_ID)"
	@echo "  Commit: $(GIT_COMMIT)"
	@echo "  ======================================================"
	@echo ""

.PHONY: all run test clean plugins tools package install release
