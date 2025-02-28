#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <inttypes.h>
#include <time.h>
#include <limits.h>


size_t lzfse_decode_buffer(uint8_t *__restrict dst_buffer,
                                     size_t dst_size,
                                     const uint8_t *__restrict src_buffer,
                                     size_t src_size,
                                     void *__restrict scratch_buffer);

size_t get_binary_size(const char *signedShortcutPath) {
    FILE *fp = fopen(signedShortcutPath,"r");
    if (!fp) {
        fprintf(stderr,"shortcut-sign: get_binary_size failed to open path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fclose(fp);
    return binary_size;
}

struct libshortcutsign_header_info {
    char *header;
    int keyCount;
    uint32_t fieldKeys[30];
    uint32_t fieldKeyPositions[30];
    uint32_t currentPos;
};

uint32_t get_aa_header_field_key(struct libshortcutsign_header_info info, uint32_t i) {
    if (i >= info.keyCount) {
        fprintf(stderr, "libshortcutsign: get_aa_header_field_key index %d out of bounds of %d\n", i, info.keyCount);
        exit(1);
    }
    /* return *(info.fieldKeys + (i << 2)); */
    return info.fieldKeys[i];
}

int aa_header_field_key_exists(struct libshortcutsign_header_info info, const char *key) {
    uint32_t key_ugly_hack = *(uint32_t *)&key;
    int keyCount = info.keyCount;
    unsigned int i;
    for (i = 0; i < keyCount; i++) {
        if (get_aa_header_field_key(info, i) == key_ugly_hack) {
            return 1;
        }
    }
    /* key not found */
    return 0;
}

int aa_header_field_key_index_by_name(struct libshortcutsign_header_info info, const char *key) {
    uint32_t key_ugly_hack = *(uint32_t *)&key;
    int keyCount = info.keyCount;
    unsigned int i;
    for (i = 0; i < keyCount; i++) {
        if (get_aa_header_field_key(info, i) == key_ugly_hack) {
            return i;
        }
    }
    /* key not found */
    return -1;
}

void *register_aa_header_field_key(struct libshortcutsign_header_info *info, const char *key, uint32_t valueSize) {
    int index = aa_header_field_key_index_by_name(*info, key);
    if (index == -1) {
        /* Add key */
        int keyCount = info->keyCount;
        info->fieldKeys[keyCount] = *(uint32_t *) &key;
        uint32_t currentPos = info->currentPos;
        char *header = info->header;
        strncpy(header + currentPos, key, 4);
        info->fieldKeyPositions[keyCount] = currentPos;
        info->keyCount = keyCount + 1;
        uint32_t valuePos = currentPos + 4;
        currentPos = valueSize + valuePos;
        info->currentPos = currentPos;
        /* Return pointer to value of key in aa header */
        struct libshortcutsign_header_info info_real = *info;
        return (info->header + valuePos);
    }
    printf("key %s already existed\n",key);
    return 0;
}

/*
 * fill_aa_file_header_with_field_keys
 *
 * Fills the header with the field keys
 * that signed shortcut files have.
 */
void fill_aa_file_header_with_field_keys(char *header, time_t currentTime) {
    struct libshortcutsign_header_info info;
    memset(&info, 0, sizeof(info));
    info.header = header;
    info.keyCount = 0;
    info.currentPos = 6;
    uint8_t aaEntryTypeRegularFile = 'F';
    struct libshortcutsign_header_info *info_ptr = &info;
    /* memcpy(register_aa_header_field_key(info_ptr, "TYP1", 1), &aaEntryTypeRegularFile, 1); */
    *(uint8_t *)register_aa_header_field_key(info_ptr, "TYP1", 1) = 'F';
    void *patp_ptr = register_aa_header_field_key(info_ptr, "PATP", 16);
    *(*(uint8_t **) &patp_ptr) = 14;
    strcpy(patp_ptr + 2, "Shortcut.wflow");
    uint32_t filePermMode = 0x1a4;
    memcpy(register_aa_header_field_key(info_ptr, "MOD2", 2), &filePermMode, 2);
    register_aa_header_field_key(info_ptr, "FLG1", 1);
    /* use currentTime for creation and modification time */
    memcpy(register_aa_header_field_key(info_ptr, "CTMT", 12), &currentTime, 4);
    memcpy(register_aa_header_field_key(info_ptr, "MTMT", 12), &currentTime, 4);
    register_aa_header_field_key(info_ptr, "DATA", 2);
}

/*
 * fill_aa_dir_header_with_field_keys
 *
 * Fills the header with the field keys
 * that signed shortcut directories have.
 */
void fill_aa_dir_header_with_field_keys(char *header, time_t currentTime) {
    struct libshortcutsign_header_info info;
    memset(&info, 0, sizeof(info));
    info.header = header;
    info.keyCount = 0;
    info.currentPos = 6;
    uint8_t aaEntryTypeRegularFile = 'D';
    struct libshortcutsign_header_info *info_ptr = &info;
    *(uint8_t *)register_aa_header_field_key(info_ptr, "TYP1", 1) = 'D';
    register_aa_header_field_key(info_ptr, "PATP", 2);
    uint32_t filePermMode = 0x1ed;
    memcpy(register_aa_header_field_key(info_ptr, "MOD2", 2), &filePermMode, 2);
    register_aa_header_field_key(info_ptr, "FLG1", 1);
    /* use currentTime for creation and modification time */
    memcpy(register_aa_header_field_key(info_ptr, "CTMT", 12), &currentTime, 4);
    memcpy(register_aa_header_field_key(info_ptr, "MTMT", 12), &currentTime, 4);
}

uint8_t *create_shortcuts_apple_archive(const char *unsignedShortcutPath, size_t *sz) {
    size_t unsignedShortcutSize = get_binary_size(unsignedShortcutPath);
    time_t currentDate = time(NULL);
    char *defaultFileHeader = malloc(82);
    uint32_t magic = 0x31304141; /* AA01 */
    memset(defaultFileHeader, 0, 82);
    memcpy(defaultFileHeader, &magic, 4);
    unsigned short aaHeaderSize;
    fill_aa_file_header_with_field_keys(defaultFileHeader, currentDate);
    if (unsignedShortcutSize > USHRT_MAX) {
        memcpy(defaultFileHeader + 78, &unsignedShortcutSize, 4);
        defaultFileHeader[77] = 'B';
        aaHeaderSize = 82;
    } else {
        /* Shortcuts smaller than USHRT_MAX are DATA not DATB */
        memcpy(defaultFileHeader + 78, &unsignedShortcutSize, 2);
        defaultFileHeader[77] = 'A';
        aaHeaderSize = 80;
    }
    memcpy(defaultFileHeader + 4, &aaHeaderSize, 2);
    size_t appleArchiveSize = aaHeaderSize + 60 + unsignedShortcutSize;
    char *appleArchive = malloc(appleArchiveSize);
    memcpy(appleArchive, &magic, 4);
    appleArchive[4] = 60;
    fill_aa_dir_header_with_field_keys(appleArchive, currentDate);
    memcpy(appleArchive + 60, defaultFileHeader, aaHeaderSize);
    free(defaultFileHeader);

    /* load AEA archive into memory */
    FILE *fp = fopen(unsignedShortcutPath,"r");
    if (!fp) {
        fprintf(stderr,"shortcut-sign: create_shortcuts_apple_archive failed to open path\n");
        free(appleArchive);
        return 0;
    }
    /* copy bytes to binary, byte by byte... */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
        appleArchive[60 + aaHeaderSize + n] = (char) c;
        n++;
    }
    fclose(fp);
    /* This check needs to be here or else someone can race this function and cause memory disclosure */
    if (n != unsignedShortcutSize) {
        fprintf(stderr,"shortcut-sign: could not read entire file\n");
        free(appleArchive);
        return 0;
    }
    if (sz) {
        *sz = 60 + aaHeaderSize + unsignedShortcutSize;
    }
    return *(uint8_t **)&appleArchive;
}

uint8_t *ext(uint8_t *encodedAppleArchive, size_t encodedAEASize, unsigned long offset, size_t *aaSize) {
    uint8_t *aaLZFSEPtr = encodedAppleArchive + offset;
    size_t decode_size = 0x100000; /* Assume AA Archive is 1MB or less */
    uint8_t *buffer = malloc(decode_size);
    *aaSize = lzfse_decode_buffer(buffer, decode_size, aaLZFSEPtr, encodedAEASize, 0);
    if (!buffer) {
        fprintf(stderr,"shortcut-sign: failed to decompress LZFSE\n");
        return 0;
    }
    return buffer;
}

uint8_t *ext_aa_from_aea(const char *signedShortcutPath, size_t *aaSize) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"r");
    if (!fp) {
        fprintf(stderr,"shortcut-sign: ext failed to find path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *aeaShortcutArchive = malloc(binary_size * sizeof(char));
    /*
     * Explained better in comment below, but
     * a process may write to a file while
     * this is going on so binary_size would be
     * bigger than the bytes we copy,
     * making it hit EOF before binary_size
     * is hit. This means that potentially
     * other memory from the process may
     * be kept here. To prevent this,
     * we 0 out our buffer to make sure
     * it doesn't contain any leftover memory
     * left.
     */
    memset(aeaShortcutArchive, 0, binary_size * sizeof(char));
    /* copy bytes to binary, byte by byte... */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
        if (n > binary_size) {
            /*
             * If, at any point, a file is modified during / before copy,
             * ex it has a really small size, but another process
             * quickly modifies it after binary_size is saved but
             * before / during the bytes are copied to the buffer,
             * then it would go past the buffer, resulting
             * in a heap overflow from our race. Fixing this
             * problem by checking if n ever reaches past
             * the initial binary_size...
             */
            free(aeaShortcutArchive);
            fclose(fp);
            fprintf(stderr,"libshortcutsign: extract_signed_shortcut reached past binarySize\n");
            return 0;
        }
        aeaShortcutArchive[n++] = (char) c;
    }
    fclose(fp);
    /* find the size of AEA_CONTEXT_FIELD_AUTH_DATA field blob */
    /* We assume it's located at 0x8-0xB */
    register const char *sptr = aeaShortcutArchive + 0xB;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    if (buf_size > binary_size-0x495c) {
        /*
         * The encrypted data for for signed shortcuts, both contact signed
         * and icloud signed, should be at buf_size+0x495c. If our buf_size
         * reaches to or past the encrypted data, then it's too big.
         */
        fprintf(stderr,"libshortcutsign: buf_size reaches past data start\n");
        return 0;
    }
    /* Decompress the LZFSE-compressed data */
    size_t aarSize;
    uint8_t *aaRawArchive = ext((uint8_t *)aeaShortcutArchive, binary_size, buf_size + 0x495c, &aarSize);
    free(aeaShortcutArchive);
    if (!aaRawArchive) {
        return 0;
    }
    if (aaSize) {
        *aaSize = aarSize;
    }
    return aaRawArchive;
}