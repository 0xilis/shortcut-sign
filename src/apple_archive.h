/*
 * Snoolie K, (c) 2025.
 * temporary apple archive parsing
 * (will be replaced with libNeoAppleArchive later)
*/

#ifndef shortcutsign_apple_archive_h
#define shortcutsign_apple_archive_h

#include <inttypes.h>

uint8_t *create_shortcuts_apple_archive(const char *unsignedShortcutPath, size_t *sz);
uint8_t *ext_aa_from_aea(const char *unsignedShortcutPath, size_t *aaSize);

#endif /* shortcutsign_apple_archive_h */