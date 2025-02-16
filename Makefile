buildDir = build
CC = clang

output: $(buildDir)
	@ # Build libshortcutsign.a
	@$(CC) -c lib/libshortcutsign/*.c -Os
	@mv neo_aa_header.o build/obj/neo_aa_header.o
	@mv libNeoAppleArchive_internal.o build/obj/libNeoAppleArchive_internal.o
	@mv libNeoAppleArchive.o build/obj/libNeoAppleArchive.o
	@ar rcs build/usr/lib/libNeoAppleArchive.a build/obj/*.o
	@ # Build fcproj CLI tool
	@$(CC) src/cli/*.c build/usr/lib/libNeoAppleArchive.a src/lib/compression/lzfse/liblzfse.a -o build/usr/bin/neoaa -lz -Os

$(buildDir):
	@echo "Creating Build Directory"
	mkdir -p build/usr/lib
	mkdir build/usr/bin
	mkdir build/obj
