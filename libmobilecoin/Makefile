# Copyright (c) 2018-2021 The MobileCoin Foundation

####################################
######### Public Variables #########
####################################

### Project Environment Variables

export SGX_MODE ?= HW
export IAS_MODE ?= DEV

### Build Configuration

CARGO_PROFILE ?= release
CARGO_BUILD_FLAGS ?=
CARGO_TARGET_DIR ?= ../target

### Toolchai

CARGO ?= cargo

####################################
######## Internal Variables ########
####################################

### Environment Variables

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  export LIBCLANG_PATH = $(shell brew --prefix llvm)/lib
endif

### Local Variables

CARGO_PACKAGE = libmobilecoin

# Status Quo, works with stripping code
ARCHS_IOS = x86_64-apple-ios aarch64-apple-ios

# builds, but does not work with stripping code
#
# $ make
# ....
# ld: building for iOS Simulator, but linking in object file built for iOS, file 'extracted/aes_nohw.o' for architecture arm64
# make: *** [aarch64-apple-ios-sim] Error 1
#ARCHS_IOS = aarch64-apple-ios-sim x86_64-apple-ios-macabi

# All targets needed:
#ARCHS_IOS = x86_64-apple-ios aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-ios-macabi x86_64-apple-ios-macabi
IOS_LIB = libmobilecoin.a
IOS_LIB_STRIPPED = libmobilecoin_stripped.a
IOS_C_HEADERS = include/*

####################################
############## Targets #############
####################################

.PHONY: all
all: setup ios

.PHONY: setup
setup:
	rustup target add $(ARCHS_IOS) || true
	rustup component add llvm-tools-preview
	rustup run --install stable cargo install cargo-binutils

.PHONY: ios
ios: out/ios/$(IOS_LIB)

CARGO_BUILD_FLAGS += --lib -Z avoid-dev-deps -Z build-std
ifeq ($(CARGO_PROFILE),release)
  BUILD_CONFIG_FOLDER = release
  CARGO_BUILD_FLAGS += --release
else
  BUILD_CONFIG_FOLDER = debug
endif

.PHONY: $(ARCHS_IOS)
x86_64-apple-ios aarch64-apple-ios aarch-apple-ios-sim aarch64-apple-ios-macabi x86_64-apple-ios-macabi: CARGO_ENV_FLAGS += CFLAGS="-DPB_NO_PACKED_STRUCTS=1"
x86_64-apple-ios aarch64-apple-ios aarch-apple-ios-sim aarch64-apple-ios-macabi x86_64-apple-ios-macabi: CARGO_ENV_FLAGS += CXXFLAGS="-DPB_NO_PACKED_STRUCTS=1"
x86_64-apple-ios: LD_ARCH = x86_64
x86_64-apple-ios-macabi: LD_ARCH = x86_64
aarch64-apple-ios: LD_ARCH = arm64
aarch64-apple-ios-sim: LD_ARCH = arm64
aarch64-apple-ios-macabi: LD_ARCH = arm64
$(ARCHS_IOS):
	$(CARGO_ENV_FLAGS) $(CARGO) build --package $(CARGO_PACKAGE) --target $@ $(CARGO_BUILD_FLAGS)

	@# Extract object files from static archive.
	@cd $(CARGO_TARGET_DIR)/$@/$(BUILD_CONFIG_FOLDER) && \
		rm -rf extracted 2>/dev/null; \
		mkdir -p extracted
	cd $(CARGO_TARGET_DIR)/$@/$(BUILD_CONFIG_FOLDER)/extracted && \
		ar -t ../$(IOS_LIB) \
			| grep '\.o$$' \
			| xargs ar -x ../$(IOS_LIB)

	@# Create list of libmobilecoin symbols.
	cd $(CARGO_TARGET_DIR)/$@/$(BUILD_CONFIG_FOLDER) && \
		rust-nm -jgU extracted/mobilecoin*.mobilecoin.*.o -s __TEXT __text \
			| grep '\<_mc_' \
			> exported-symbols.def

	@# Link extracted object files back into static arch. Removes all symbols not needed
	@# by exported libmobilecoin symbols.
	@cd $(CARGO_TARGET_DIR)/$@/$(BUILD_CONFIG_FOLDER) && \
		rm -f $(IOS_LIB_STRIPPED) || true
	cd $(CARGO_TARGET_DIR)/$@/$(BUILD_CONFIG_FOLDER) && \
		ld -r -arch $(LD_ARCH) -x -keep_private_externs \
			-exported_symbols_list exported-symbols.def \
			-o $(IOS_LIB_STRIPPED) \
			extracted/*.o


.PHONY: out/ios/$(IOS_LIB)
out/ios/$(IOS_LIB): $(ARCHS_IOS)
	mkdir -p out/ios
	# Create arch specific folders for each lib
	$(foreach arch,$^,mkdir -p out/ios/$(arch);) 

	$(foreach arch,$^,cp $(CARGO_TARGET_DIR)/$(arch)/$(BUILD_CONFIG_FOLDER)/${IOS_LIB} out/ios/$(arch);)
	$(foreach arch,$^,cp $(CARGO_TARGET_DIR)/$(arch)/$(BUILD_CONFIG_FOLDER)/${IOS_LIB_STRIPPED} out/ios/$(arch);)

	mkdir -p out/ios/include
	cp $(IOS_C_HEADERS) out/ios/include

.PHONY: clean
clean:
	@rm -r out 2>/dev/null || true

####################################
############# Commands #############
####################################

.PHONY: setup-dev
setup-dev:
	cargo install cbindgen

.PHONY: cbindgen
cbindgen:
	cbindgen --crate libmobilecoin -o libmobilecoin_cbindgen.h
