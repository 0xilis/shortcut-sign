buildDir = build
CC = clang

BUILD_DIR = ../../build/libshortcutsign

output: $(buildDir)
	@ # Build libshortcutsign.a
	@echo "building libshortcutsign..."
	@$(CC) -c lib/libshortcutsign/xplat.c -o build/obj/xplat.o -Os
	@$(CC) -c lib/libshortcutsign/sign.c -o build/obj/sign.o -Os
	@ar rcs build/usr/lib/libshortcutsign.a build/obj/*.o
	@ # Build shortcut-sign CLI tool
	@echo "building shortcut-sign..."
	@$(CC) src/*.c build/usr/lib/libshortcutsign.a lib/libshortcutsign/build/lzfse/lib/liblzfse.a lib/libshortcutsign/libs/libNeoAppleArchive/build/usr/lib/libNeoAppleArchive.a -o build/usr/bin/shortcut-sign -lz -Os

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir build/usr/bin
	mkdir build/obj
	mkdir build/libshortcutsign
	mkdir build/lzfse