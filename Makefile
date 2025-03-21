buildDir = build
CC = clang
CFLAGS = -Os -std=c89 -Ibuild/lzfse/include -Ibuild/libzbitmap/include -Ilib/libshortcutsign

LIBSHORTCUTSIGN_DIR = lib/libshortcutsign

output: $(buildDir)
	@ # Build libshortcutsign
	@echo "building libshortcutsign..."
	$(MAKE) -C $(LIBSHORTCUTSIGN_DIR)

	@ # Build shortcut-sign CLI tool
	@echo "building shortcut-sign..."
	@$(CC) src/*.c lib/libshortcutsign/build/usr/lib/libshortcutsign.a -Llib/libshortcutsign/build/lzfse/lib -Llib/libshortcutsign/libs/libNeoAppleArchive/build/libzbitmap/lib -Llib/libshortcutsign/libs/libNeoAppleArchive/build/usr/lib -o build/usr/bin/shortcut-sign -llzfse -lNeoAppleArchive -lzbitmap -lz -lssl -lcrypto -lplist-2.0 $(CFLAGS)

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir -p build/usr/bin
	mkdir -p build/obj
	mkdir -p build/libshortcutsign
	mkdir -p build/lzfse
	mkdir -p build/libNeoAppleArchive