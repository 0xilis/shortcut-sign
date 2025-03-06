#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libplist/libplist.h>

__attribute__((visibility ("hidden"))) static char *load_file_into_memory(const char *path, size_t *size) {
    /* load shortcut into memory */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        NSLog(@"QuickMerge Helper: Failed to open file");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *archive = malloc(binarySize);
    /* copy bytes to binary */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
     archive[n++] = (char) c;
    }
    fclose(fp);
    if (size) {
        *size = binarySize;
    }
    return archive;
}
/* WARNING: Do not rely on this as reliable encryption to keep you safe, easily defeatable. */
char *load_file_into_memory_with_bitflip_keys(const char *path, size_t size, unsigned long long bitflip, unsigned long sizekey) {
    /* bitflip and sizekey are different as knowing the private key size and 04 bitflip is easily guessable */
    /* load shortcut into memory */
    FILE *fp = fopen(path, "r");
    if (!fp) {
        NSLog(@"QuickMerge Helper: Failed to open file");
        return 0;
    }
    char *archive = malloc(size * sizeof(char));
    /* skip first 4 bytes */
    for (int i = 0; i < 4; i++) {
        fgetc(fp);
    }
    unsigned int bitshift = 24;
    /* qmd h*/
    for (int i = 4; i < 8; i++) {
        archive[i] = (((char)fgetc(fp)) ^ ((bitflip >> bitshift) & 0xFF));
        bitshift -= 8;
    }
    /* first byte of ECDSA key will not be flipped */
    archive[8] = (char)fgetc(fp);
    /* copy bytes to binary */
    bitshift = 56;
    int c;
    size_t n = 9;
    char lastDecryptedChar = 0;
    while ((c = fgetc(fp)) != EOF) {
        lastDecryptedChar = (((char) c) ^ (((bitflip >> bitshift) & 0xFF) ^ lastDecryptedChar));
        archive[n++] = lastDecryptedChar;
        bitshift -= 8;
        if (bitshift > 64) {
            bitshift = 56;
        }
    }
    fclose(fp);
    /* PATCHWORK FIX: We accidentally flip the magic so fix it */
    archive[0] = 'Q';
    archive[1] = 'M';
    archive[2] = 'D';
    archive[3] = '\0';
    return archive;
}
/* Gives signing private key data for raw .qmd (QuickMerge Raw Data) */
uint8_t *signing_private_key_for_raw_qmd(const char *path) {
    size_t fileSize = get_file_size(path);
    if (!fileSize) { return 0; };
    char *archive = load_file_into_memory(path, 0);
    if (!archive) { return 0; };
    /* The len of the private signing key is the lower 32 bits of the first quadword */
    /* Highest 32 bits of quadword are "QMD\0" */
    register const char *sptr = archive + 0x7;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    last_loaded_file_key_size = buf_size;
    if (buf_size > fileSize-8) {
        fprintf(stderr,"QuickMerge Helper: buf_size reaches past fileSize\n");
        return 0;
    }
    /* we got buf_size, now fill buffer */
    uint8_t *buffer = (uint8_t *)malloc(buf_size);
    /*
     * the reason why we are doing a reverse
     * iteration is because doing it this way
     * will allow arm devices to take advantage
     * of the cbnz instruction, which should
     * mean about a 2 cycle save per iteration.
     *
     * also we're going to blindly trust that buf_size
     * is not larger than the buffer, because unless
     * you malform a aea file it should never be.
    */
    unsigned long i = buf_size;
    fill_buffer:
    i--;
    buffer[i] = archive[i+0x8];
    if (i != 0) {goto fill_buffer;};
    free(archive);
    return buffer;
}
/* Gives signing private key data for raw .qmd (QuickMerge Raw Data) */
uint8_t *signing_private_key_for_raw_qmd_bitflip(const char *path, unsigned long long bitflip, unsigned long sizekey) {
    size_t fileSize = get_file_size(path);
    if (!fileSize) { return 0; };
    char *archive = load_file_into_memory_with_bitflip_keys(path, fileSize, bitflip, sizekey);
    if (!archive) { return 0; };
    /* The len of the private signing key is the lower 32 bits of the first quadword */
    /* Highest 32 bits of quadword are "QMD\0" */
    register const char *sptr = archive + 0x7;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    last_loaded_file_key_size = buf_size;
    if (buf_size > fileSize-8) {
        fprintf(stderr,"QuickMerge Helper: buf_size reaches past fileSize\n");
        return 0;
    }
    /* we got buf_size, now fill buffer */
    uint8_t *buffer = (uint8_t *)malloc(buf_size);
    /*
     * the reason why we are doing a reverse
     * iteration is because doing it this way
     * will allow arm devices to take advantage
     * of the cbnz instruction, which should
     * mean about a 2 cycle save per iteration.
     *
     * also we're going to blindly trust that buf_size
     * is not larger than the buffer, because unless
     * you malform a aea file it should never be.
    */
    unsigned long i = buf_size;
    fill_buffer:
    i--;
    buffer[i] = archive[i+0x8];
    if (i != 0) {goto fill_buffer;};
    free(archive);
    return buffer;
}
/* Gives signing private key data for raw .qmd (QuickMerge Raw Data) */
uint8_t *signing_auth_data_for_raw_qmd(const char *path) {
    size_t fileSize = get_file_size(path);
    if (!fileSize) { return 0; };
    char *archive = load_file_into_memory(path, 0);
    if (!archive) { return 0; };
    /* The len of the private signing key is the lower 32 bits of the first quadword */
    /* Highest 32 bits of quadword are "QMC\0" */
    register const char *sptr = archive + 0x7;
    size_t buf_size = *sptr << 24;
    buf_size += *(sptr - 1) << 16;
    buf_size += *(sptr - 2) << 8;
    buf_size += *(sptr - 3);
    if (buf_size > fileSize-8) {
        fprintf(stderr,"QuickMerge Helper: buf_size reaches past fileSize\n");
        return 0;
    }
    /* Get starting position of auth data */
    unsigned long long offset = 0x8+buf_size;
    size_t auth_size = fileSize-offset;
    last_loaded_file_key_size = auth_size;
    /* we got buf_size, now fill buffer */
    uint8_t *buffer = (uint8_t *)malloc(auth_size);
    /*
     * the reason why we are doing a reverse
     * iteration is because doing it this way
     * will allow arm devices to take advantage
     * of the cbnz instruction, which should
     * mean about a 2 cycle save per iteration.
     *
     * also we're going to blindly trust that buf_size
     * is not larger than the buffer, because unless
     * you malform a aea file it should never be.
    */
    unsigned long i = auth_size;
    fill_auth_data:
    i--;
    buffer[i] = archive[i+offset];
    if (i != 0) {goto fill_auth_data;};
    free(archive);
    return buffer;
}

/* Gives signing private key data for .qmc (QuickMerge Context) */
uint8_t *signing_private_key_for_qmc_path(const char* qmcPath) {
    plist_t qmcInfoPlist;
    size_t qmcaSize = 0;
    size_t infoPlistSize = 0;
    struct stat s;
    if (stat(path,&s)) {
        fprintf(stderr,"libqmc: stat failed\n");
        return 0;
    }
    if (s.st_mode & S_IFDIR) {
        /* QMCv1: Directory/Bundle */
        char qmcInfoPath[1024];
        snprintf(qmcInfoPath, sizeof(qmcInfoPath), "%s/Info.plist", qmcPath);
        qmcInfoPlist = plist_new_from_file(qmcInfoPath);
    } else if (s.st_mode & S_IFREG) {
        /* QMCA/QMC2: QMC Archive */
        const char *qmca = (const char *)load_file_into_memory(qmcPath, &qmcaSize);
        if (strncmp(qmca, "QMCA", 4)) {
            fprintf(stderr,"libqmc: does not have QMCA magic\n");
            return 0;
        }
        register const char *sptr = qmca + 4;
        infoPlistSize = *sptr << 24;
        infoPlistSize += *(sptr - 1) << 16;
        infoPlistSize += *(sptr - 2) << 8;
        infoPlistSize += *(sptr - 3);
        if (plist_from_memory(qmca + 8, infoPlistSize, &qmcInfoPlist, 0) != PLIST_ERR_SUCCESS) {
            fprintf(stderr, "libqmc: failed to read plist from file\n");
            return -1;
        }
    } else {
        fprintf(stderr,"libqmc: not file or directory\n");
        return 0;
    }

    if (qmcInfoPlist) {
        plist_t typeObj = plist_dict_get_item(qmcInfoPlist, "type");
        if (typeObj) {
            uint64_t type;
            plist_get_uinteger_val(typeObj, &type);
            char qmdPath[1024];
            snprintf(qmdPath, sizeof(qmdPath), "%s/data.qmd", qmcPath);
            if (type == QMC_RAW) {
                uint8_t* privateKey = signing_private_key_for_raw_qmd(qmdPath);
                if (privateKey) {
                    return privateKey;
                }
            } else if (type == QMC_OPTIMIZED) {
                /* Handle optimized case (not implemented) */
            } else if (type == QMC_RAW_FLIP) {
                plist_t bkeyObj = plist_dict_get_item(qmcInfoPlist, "bk");
                plist_t skeyObj = plist_dict_get_item(qmcInfoPlist, "sk");
                unsigned long long bkey = 0;
                unsigned long skey = 0;
                if (bkeyObj) {
                    plist_get_uinteger_val(bkeyObj, &bkey);
                }
                if (skeyObj) {
                    plist_get_uinteger_val(skeyObj, &skey);
                }
                uint8_t *privateKey = signing_private_key_for_raw_qmd_bitflip(qmdPath, bkey, skey);
                if (privateKey) {
                    return privateKey;
                }
            } else {
                /* Unrecognized QMC type. */
                return NULL;
            }
        }
    }
    return NULL;
}

/* Gives signing auth data for .qmc (QuickMerge Context) */
uint8_t *signing_auth_data_for_qmc_path(const char* qmcPath) {
    char qmcInfoPath[1024];
    snprintf(qmcInfoPath, sizeof(qmcInfoPath), "%s/Info.plist", qmcPath);

    plist_t qmcInfoPlist = plist_new_from_file(qmcInfoPath);
    if (qmcInfoPlist) {
        plist_t typeObj = plist_dict_get_item(qmcInfoPlist, "type");
        if (typeObj) {
            uint64_t type;
            plist_get_uinteger_val(typeObj, &type);
            char qmd[1024];
            snprintf(qmd, sizeof(qmd), "%s/data.qmd", qmcPath);
            if (type == QMC_RAW) {
                uint8_t* buffer = signing_auth_data_for_raw_qmd(qmd);
                if (buffer) {
                    return buffer;
                }
            } else if (type == QMC_OPTIMIZED) {
                /* Handle optimized case (not implemented) */
            } else if (type == QMC_RAW_FLIP) {
                /* In future add support using skey later */
                uint8_t *buffer = signing_auth_data_for_raw_qmd(qmd);
                if (buffer) {
                    return buffer;
                }
            } else {
                /* Unrecognized QMC type. */
                return NULL;
            }
        }
    }
    return NULL;
}
