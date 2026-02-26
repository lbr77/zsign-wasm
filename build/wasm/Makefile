EMSDK_ENV ?= /Users/libr/Desktop/Life/emsdk/emsdk_env.sh
OPENSSL_WASM ?= ../../../openssl-wasm/precompiled

EMXX := . "$(EMSDK_ENV)" >/dev/null 2>&1 && em++
CXXFLAGS = -std=c++17 -O3 -Wno-unused-result
CXXFLAGS += -I../../src -I../../src/common
CXXFLAGS += -I$(OPENSSL_WASM)/include

LDFLAGS = $(OPENSSL_WASM)/lib/libcrypto.a $(OPENSSL_WASM)/lib/libssl.a
LDFLAGS += -sERROR_ON_UNDEFINED_SYMBOLS=1
LDFLAGS += -sALLOW_MEMORY_GROWTH=1
LDFLAGS += -sENVIRONMENT=web,worker,node
LDFLAGS += -sFORCE_FILESYSTEM=1
LDFLAGS += -sMODULARIZE=1
LDFLAGS += -sEXPORT_NAME=createZsignModule
LDFLAGS += -sEXPORT_ALL=1
LDFLAGS += --post-js ../../src/wasm_post.js

OBJDIR = .build
BINDIR = ../../bin
TARGET = $(BINDIR)/zsign-wasm.js
DISTDIR = ../../dist
CLIENT = ZsignWasmClient.js
SINGLE = $(DISTDIR)/zsign-wasm.min.js
PACKER = pack-single.js

SRCS = ../../src/archo.cpp
SRCS += ../../src/macho.cpp
SRCS += ../../src/openssl.cpp
SRCS += ../../src/signing.cpp
SRCS += ../../src/zsign_export.cpp
SRCS += ../../src/common/base64.cpp
SRCS += ../../src/common/fs.cpp
SRCS += ../../src/common/json.cpp
SRCS += ../../src/common/log.cpp
SRCS += ../../src/common/sha.cpp
SRCS += ../../src/common/timer.cpp
SRCS += ../../src/common/util.cpp
SRCS += ../../src/common/wasm_compat.cpp

LDFLAGS += -sEXPORTED_FUNCTIONS='["_zsign_version","_zsign_set_log_level","_zsign_sign_macho","_zsign_sign_macho_mem","_zsign_free_buffer","_malloc","_free"]'
LDFLAGS += -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","stringToUTF8","lengthBytesUTF8","HEAPU8","HEAPU32"]'

OBJS = $(SRCS:../../src/%.cpp=$(OBJDIR)/%.o)

all: $(TARGET)
	@echo ">>> Build OK -> $(abspath $(TARGET))"

bundle: $(TARGET) $(SINGLE)
	@mkdir -p $(DISTDIR)
	@cp -f $(TARGET) $(DISTDIR)/zsign-wasm.js
	@cp -f $(TARGET:.js=.wasm) $(DISTDIR)/zsign-wasm.wasm
	@cp -f $(CLIENT) $(DISTDIR)/$(CLIENT)
	@printf "module.exports = require('./ZsignWasmClient');\n" > $(DISTDIR)/index.js
	@echo ">>> Bundle OK -> $(abspath $(DISTDIR))"

$(SINGLE): $(TARGET) $(TARGET:.js=.wasm) $(CLIENT) $(PACKER)
	@mkdir -p $(DISTDIR)
	@node $(PACKER) $(TARGET) $(TARGET:.js=.wasm) $(CLIENT) $(SINGLE)
	@echo ">>> Single File OK -> $(abspath $(SINGLE))"

$(TARGET): $(OBJS)
	@mkdir -p $(BINDIR)
	@$(EMXX) $(OBJS) $(LDFLAGS) -o $(TARGET)

$(OBJDIR)/%.o: ../../src/%.cpp
	@mkdir -p $(dir $@)
	@$(EMXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET) $(TARGET:.js=.wasm) $(DISTDIR)
	@echo ">>> Clean OK"

.PHONY: all bundle clean
