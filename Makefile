.PHONY: all clean install configure

BUILD_DIR := build
CMAKE     ?= cmake
GENERATOR ?= $(shell command -v ninja >/dev/null 2>&1 && echo Ninja || echo "Unix Makefiles")

all: configure
	@$(CMAKE) --build $(BUILD_DIR) --config Release -j$(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

configure: $(BUILD_DIR)/CMakeCache.txt

$(BUILD_DIR)/CMakeCache.txt:
	@mkdir -p $(BUILD_DIR)
	@$(CMAKE) -S . -B $(BUILD_DIR) -G "$(GENERATOR)" -DCMAKE_BUILD_TYPE=Release

clean:
	@rm -rf $(BUILD_DIR)

install: all
	@mkdir -p ~/.idapro/plugins
	@uname_s=$$(uname); \
	if [ "$$uname_s" = "Darwin" ]; then \
		f=$$(find $(BUILD_DIR) -name 'codedump.dylib' -type f | head -n1); \
		cp "$$f" ~/.idapro/plugins/; \
		codesign -s - -f ~/.idapro/plugins/codedump.dylib; \
	elif [ "$$uname_s" = "Linux" ]; then \
		f=$$(find $(BUILD_DIR) -name 'codedump.so' -type f | head -n1); \
		cp "$$f" ~/.idapro/plugins/; \
	else \
		f=$$(find $(BUILD_DIR) -name 'codedump.dll' -type f | head -n1); \
		cp "$$f" ~/.idapro/plugins/; \
	fi; \
	echo "Installed codedump plugin to ~/.idapro/plugins/"
