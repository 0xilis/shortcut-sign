buildDir = build
CC = clang
CFLAGS = -Os -std=c89

BUILD_DIR = ../../build/libshortcutsign

LZFSE_DIR = lib/libshortcutsign/libs/lzfse
BUILD_LZFSE_DIR = ../../build/lzfse

NEOAPPLEARCHIVE_DIR = lib/libshortcutsign/libs/libNeoAppleArchive

output: $(buildDir)
	@ # Build liblzfse submodule
	@echo "building liblzfse..."
	$(MAKE) -C $(LZFSE_DIR) install INSTALL_PREFIX=$(BUILD_LZFSE_DIR)

	@ # Build libNeoAppleArchive submodule
	@echo "building libNeoAppleArchive..."
	$(MAKE) -C $(NEOAPPLEARCHIVE_DIR)

	@ # Build libshortcutsign.a
	@echo "building libshortcutsign..."
	@$(CC) -c lib/libshortcutsign/extract.c -o build/obj/extract.o $(CFLAGS)
	@$(CC) -c lib/libshortcutsign/sign.c -o build/obj/sign.o $(CFLAGS)
	@$(CC) -c lib/libshortcutsign/verify.c -o build/obj/verify.o $(CFLAGS)
	@$(CC) -c lib/libshortcutsign/res.c -o build/obj/res.o $(CFLAGS)
	@ar rcs build/usr/lib/libshortcutsign.a build/obj/*.o
	@ # Build shortcut-sign CLI tool
	@echo "building shortcut-sign..."
	@$(CC) src/*.c build/usr/lib/libshortcutsign.a lib/libshortcutsign/build/lzfse/lib/liblzfse.a lib/libshortcutsign/libs/libNeoAppleArchive/build/usr/lib/libNeoAppleArchive.a -o build/usr/bin/shortcut-sign -lz -lssl -lcrypto -lplist-2.0 $(CFLAGS)

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir build/usr/bin
	mkdir build/obj
	mkdir build/libshortcutsign
	mkdir build/lzfse
	mkdir build/libNeoAppleArchive