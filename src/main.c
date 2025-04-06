#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <libshortcutsign.h>

#define OPTSTR "i:o:u:k:a:hvr"

struct option long_options[] = {
    {"input", required_argument, NULL, 'i'},
    {"output", required_argument, NULL, 'o'},
    {"unsigned", required_argument, NULL, 'u'},
    {"key", required_argument, NULL, 'k'},
    {"auth", required_argument, NULL, 'a'},
    {"raw_aar", no_argument, NULL, 'r'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

typedef enum {
    SS_CMD_SIGN,
    SS_CMD_EXTRACT,
    SS_CMD_VERIFY,
    SS_CMD_AUTH_EXTRACT,
    SS_CMD_RESIGN,
    SS_CMD_VERSION,
    SS_CMD_INFO,
    SS_CMD_UPLOAD,
    SS_CMD_SIGNIN,
} SSCommand;

void show_help(void) {
    printf("Usage: shortcut-sign command <options>\n\n");
    printf("Commands:\n\n");
    printf(" sign: sign an unsigned shortcut.\n");
    printf(" extract: extract unsigned shortcut from a signed shortcut.\n");
    printf(" verify: verify signature of signed shortcut. (currently only contact-signed)\n");
    printf(" auth: extract auth data of shortcut\n");
    printf(" resign: resign a signed shortcut\n");
    printf(" info: log info about signed shortcut's signing chain\n");
    printf(" version: display version of shortcut-sign\n");
    printf("\n");
    printf("Options:\n\n");
    printf(" -i: path to the input file or directory.\n");
    printf(" -o: path to the output file or directory.\n");
    printf(" -u: optional option for resign command, for signing over shortcut with unsigned shortcut.\n");
    printf(" -k: for signing/resigning, specify file containing ASN1 private ECDSA-P256 key\n");
    printf(" -a: for signing, specify file containing auth data\n");
    printf(" -r/-raw_aar: flag to specify extracting the raw aar or sign raw aar data instead of plist\n");
    /* printf(" -q: for signing, specify QMC file instead of key/auth\n"); */
    printf(" -h: this ;-)\n");
    printf("\n");
}

__attribute__((visibility ("hidden"))) static uint8_t *load_binary(const char *signedShortcutPath, size_t *binarySize) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"rb");
    if (!fp) {
        fprintf(stderr,"shortcut-sign: load_binary could not open path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t _binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *aeaShortcutArchive = malloc(_binarySize);
    size_t n = fread(aeaShortcutArchive, 1, _binarySize, fp);
    fclose(fp);
    if (n != _binarySize) {
        fprintf(stderr,"shortcut-sign: load_binary could not read entire file\n");
        free(aeaShortcutArchive);
        return 0;
    }
    if (binarySize) {
        *binarySize = _binarySize;
    }
    return aeaShortcutArchive;
}

__attribute__((visibility ("hidden"))) static uint8_t *malloc_binaryForExpansion(const char *signedShortcutPath, size_t *binarySize, size_t extraSize) {   
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"rb");
    if (!fp) {
        fprintf(stderr,"shortcut-sign: malloc_binaryForExpansion could not open path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t _binarySize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    /* Check for integer overflow */
    size_t mallocSize = _binarySize + extraSize;
    if (mallocSize < _binarySize || mallocSize < extraSize) {
        fprintf(stderr,"shortcut-sign: malloc_binaryForExpansion overflowed size\n");
        return 0;
    }

    uint8_t *aeaShortcutArchive = malloc(mallocSize);
    /* 0 out all extra bytes we allocate, all after _binarySize */
    memset(aeaShortcutArchive + _binarySize, 0, extraSize);
    size_t n = fread(aeaShortcutArchive, 1, _binarySize, fp);
    fclose(fp);
    if (n != _binarySize) {
        fprintf(stderr,"shortcut-sign: malloc_binaryForExpansion could not read entire file\n");
        free(aeaShortcutArchive);
        return 0;
    }
    if (binarySize) {
        *binarySize = mallocSize;
    }
    return aeaShortcutArchive;
}



int main(int argc, const char * argv[]) {
    if (argc < 2) {
        show_help();
        return 0;
    }
    /* Parse commands */
    SSCommand ssCommand;
    const char *commandString = argv[1];
    if (strncmp(commandString, "sign", 4) == 0) {
        ssCommand = SS_CMD_SIGN;
    } else if (strncmp(commandString, "extract", 7) == 0) {
        ssCommand = SS_CMD_EXTRACT;
    } else if (strncmp(commandString, "verify", 4) == 0) {
        ssCommand = SS_CMD_VERIFY;
    } else if (strncmp(commandString, "auth", 4) == 0) {
        ssCommand = SS_CMD_AUTH_EXTRACT;
    } else if (strncmp(commandString, "resign", 6) == 0) {
        ssCommand = SS_CMD_RESIGN;
    } else if (strncmp(commandString, "version", 7) == 0) {
        ssCommand = SS_CMD_VERSION;
    } else if (strncmp(commandString, "-version", 8) == 0) {
        ssCommand = SS_CMD_VERSION;
    } else if (strncmp(commandString, "--version", 9) == 0) {
        ssCommand = SS_CMD_VERSION;
    } else if (strncmp(commandString, "info", 4) == 0) {
        ssCommand = SS_CMD_INFO;
    } else if (strncmp(commandString, "-h", 2) == 0) {
        show_help();
        return 0;
    } else if (strncmp(commandString, "help", 4) == 0) {
        show_help();
        return 0;
    } else if (strncmp(commandString, "--help", 6) == 0) {
        show_help();
        return 0;
    } else {
        printf("Invalid command.\n");
        show_help();
        return 0;
    }
    int rawAarFlag = 0;
    unsigned int i = 0;
    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "-raw_aar", 8) == 0) {
            rawAarFlag = 1;
            /* Remove it from argv by shifting elements to the left */
            int j = i;
            for (j = i; j < argc; j++) {
                argv[j] = argv[j + 1];
            }
            /* Adjust argc because we removed an element from argv */
            argc--;
            break;
        }
    }
    /* Hack to get getopt_long() to skip the command in argv */
    argv++;
    argc--;

    char *inputPath = NULL;
    char *outputPath = NULL;
    char *unsignedPath = NULL;
    char *privateKeyPath = NULL;
    char *authDataPath = NULL;
    int showHelp = 0;
    
    /* Parse args */
    int opt;
    while ((opt = getopt_long(argc, (char* const *)argv, OPTSTR, long_options, NULL)) != -1) {
        if (opt == 'i') {
            inputPath = optarg;
        } else if (opt == 'o') {
            outputPath = optarg;
        } else if (opt == 'u') {
            unsignedPath = optarg;
        } else if (opt == 'k') {
            privateKeyPath = optarg;
        } else if (opt == 'a') {
            authDataPath = optarg;
        } else if (opt == 'r') {
            rawAarFlag = 1;
        } else if (opt == 'h') {
            /* Show help */
            showHelp = 1;
        }
    }
    if (showHelp) {
        if (SS_CMD_SIGN == ssCommand) {
            printf("Usage: shortcut-sign sign --input <input> --output <output> --key <key> --auth <auth>\n\n");
            printf("Example: shortcut-sign sign -i unsigned.shortcut -o signed.shortcut -k privateKey.bin -a authData.plist\n\n");
            printf("Options:\n");
            printf("-i, --input <input>    path to the unsigned shortcut\n");
            printf("-o, --output <output>  path to output the signed shortcut\n");
            printf("-k, --key <key>        path to raw X9.63 ECDSA-P256 key\n");
            printf("-a, --auth <auth>      path to auth data plist for key\n\n");
        } else if (SS_CMD_EXTRACT == ssCommand) {
            printf("Usage: shortcut-sign extract --input <input> --output <output>\n\n");
            printf("Example: shortcut-sign extract -i signed.shortcut -o unsigned.shortcut\n\n");
            printf("Options:\n");
            printf("-i, --input <input>    path to the signed shortcut\n");
            printf("-o, --output <output>  path to output the unsigned shortcut\n\n");
        } else if (SS_CMD_VERIFY == ssCommand) {
            printf("Usage: shortcut-sign verify --input <input>\n\n");
            printf("Example: shortcut-sign verify -i signed.shortcut\n\n");
            printf("Options:\n");
            printf("-i, --input <input>    path to the signed shortcut\n\n");
        } else if (SS_CMD_AUTH_EXTRACT == ssCommand) {
            printf("Usage: shortcut-sign auth --input <input> --output <output>\n\n");
            printf("Example: shortcut-sign auth -i signed.shortcut -o auth.plist\n\n");
            printf("Options:\n");
            printf("-i, --input <input>    path to the signed shortcut\n");
            printf("-o, --output <output>  path to output the auth data\n\n");
        } else if (SS_CMD_RESIGN == ssCommand) {
            printf("Usage: shortcut-sign resign --input <input> --output <output> --key <key>\n\n");
            printf("Example: shortcut-sign resign -i signed.shortcut -o resigned.shortcut -k privateKey.bin\n\n");
            printf("Options:\n");
            printf("-i, --input <input>    path to the signed shortcut\n");
            printf("-o, --output <output>  path to output the resigned shortcut\n");
            printf("-k, --key <key>        path to raw X9.63 ECDSA-P256 key\n\n");
        } else if (SS_CMD_INFO == ssCommand) {
            printf("Usage: shortcut-sign info --input <input>\n\n");
            printf("Example: shortcut-sign info -i signed.shortcut\n\n");
            printf("Options:\n");
            printf("-i, --input <input>    path to the signed shortcut\n\n");
        } else {
            show_help();
        }
        return 0;
    }

    /* SS_CMD_VERSION is the only command where inputPath is not needed */
    if (SS_CMD_VERSION == ssCommand) {
        printf("1.0 Beta 5\n");
        return 0;
    }
    if (!inputPath) {
        printf("No -i specified.\n");
        show_help();
    }
    if (SS_CMD_EXTRACT == ssCommand) {
        if (!outputPath) {
            printf("No -o specified.\n");
            return 0;
        }
        if (rawAarFlag) {
            /* Not normal extraction; extract raw data (aar) */
            size_t signedShortcutSize = 0;
            uint8_t *signedShortcut = load_binary(inputPath, &signedShortcutSize);
            if (!signedShortcut) {
                printf("Failed to load input\n");
                return 0;
            }
            size_t aarSize = 0;
            uint8_t *aar = extract_signed_shortcut_buffer_aar(signedShortcut, signedShortcutSize, &aarSize);
            if (!aar) {
                printf("Failed to extract aar buffer\n");
                return 0;
            }
            FILE *fp = fopen(outputPath, "wb");
            if (!fp) {
                printf("Failed to open output file.\n");
                return 0;
            }
            fwrite(aar, aarSize, 1, fp);
            fclose(fp);
            return 0;
        }
        if (extract_signed_shortcut(inputPath, outputPath)) {
            printf("Extraction failed.\n");
            return 0;
        }
    } else if (SS_CMD_AUTH_EXTRACT == ssCommand) {
        if (!outputPath) {
            /* No outputPath specified, in the future try to print auth data then */
            printf("No -o specified.\n");
            return 0;
        }
        FILE *fp = fopen(outputPath, "wb");
        if (!fp) {
            printf("Failed to open output file.\n");
            return 0;
        }
        size_t bufferSize = 0;
        uint8_t *authData = auth_data_from_shortcut(inputPath, &bufferSize);
        if (!authData) {
            printf("Failed to receive auth data from shortcut.\n");
            return 0;
        }
        if (!bufferSize) {
            printf("Failed to receive auth data from shortcut.\n");
            return 0;
        }
        fwrite(authData, bufferSize, 1, fp);
        fclose(fp);
        free(authData);
    } else if (SS_CMD_VERIFY == ssCommand) {
        if (verify_signed_shortcut(inputPath)) {
            printf("Verification Failed\n");
        } else {
            printf("Verification Successful\n");
        }
    } else if (SS_CMD_RESIGN == ssCommand) {
        if (!outputPath) {
            /* No outputPath specified */
            printf("No -o specified.\n");
            return 0;
        }
        if (!privateKeyPath) {
            /* No privateKeyPath specified */
            printf("No -k specified.\n");
            return 0;
        }
        size_t unsignedPlistSize = 0;
        uint8_t *unsignedPlist;
        if (unsignedPath) {
            /* User specified unsigned shortcut to resign shortcut over */
            unsignedPlist = load_binary(unsignedPath, &unsignedPlistSize);
            if (!unsignedPlist) {
                printf("Failed to load unsigned plist.\n");
                return 0;
            }
        } else {
            if (rawAarFlag) {
                printf("-r/-raw_aar flag specified, but no -u for resigning\n");
                return 0;
            }
            /* Extract unsigned AA from AEA (i need to add this to libshortcutsign) */
            size_t signedShortcutSize = 0;
            uint8_t *signedShortcut = load_binary(inputPath, &signedShortcutSize);
            unsignedPlist = extract_signed_shortcut_buffer(signedShortcut, signedShortcutSize, &unsignedPlistSize);
            free(signedShortcut);
            if (!unsignedPlist) {
                printf("Unsigned plist extraction failed.\n");
                return 0;
            }
        }

        size_t aeaShortcutArchiveSize = 0;
        /* We are adding the unsigned plist to our malloc so we can expand this */
        uint8_t *aeaShortcutArchive = malloc_binaryForExpansion(inputPath, &aeaShortcutArchiveSize, unsignedPlistSize);
        if (!aeaShortcutArchive) {
            printf("Failed to load input AEA.\n");
            return 0;
        }
        uint8_t *privateKey = load_binary(privateKeyPath, 0);
        if (!privateKey) {
            printf("Failed to load private key.\n");
            return 0;
        }

        size_t resignedSize = 0;
        if (rawAarFlag) {
            if (resign_shortcut_with_new_aa(&aeaShortcutArchive, unsignedPlist, unsignedPlistSize, &resignedSize, privateKey)) {
                printf("Failed to resign shortcut with new plist.\n");
                return -1;
            }
        } else {
            if (resign_shortcut_with_new_plist(&aeaShortcutArchive, unsignedPlist, unsignedPlistSize, &resignedSize, privateKey)) {
                printf("Failed to resign shortcut with new plist.\n");
                return -1;
            }
        }

        /* resign_shortcut_with_new_plist auto frees unsignedPlist so we don't free it */
        free(privateKey);

        /* Copy final resigned archive to outputPath */
        FILE *fp = fopen(outputPath, "w");
        if (!fp) {
            free(aeaShortcutArchive);
            printf("Failed to open outputPath.\n");
            return -1;
        }
        fwrite(aeaShortcutArchive, resignedSize, 1, fp);
        fclose(fp);
        free(aeaShortcutArchive);
    } else if (SS_CMD_SIGN == ssCommand) {
        if (!outputPath) {
            /* No outputPath specified */
            printf("No -o specified.\n");
            return 0;
        }
        if (!privateKeyPath) {
            /* No privateKeyPath specified */
            printf("No -k specified.\n");
            return 0;
        }
        if (!authDataPath) {
            /* No authDataPath specified */
            printf("No -a specified.\n");
            return 0;
        }
        size_t unsignedPlistSize = 0;
        uint8_t *unsignedPlist;
        if (unsignedPath) {
            printf("Please specify the unsigned shortcut with -i and not -u; did you mean to use the resign command instead?\n");
            return 0;
        }
        unsignedPlist = load_binary(inputPath, &unsignedPlistSize);
        if (!unsignedPlist) {
            printf("Failed to load unsigned plist.\n");
            return 0;
        }
        if (!rawAarFlag) {
            if (get_shortcut_format(unsignedPlist, unsignedPlistSize) != SHORTCUT_UNSIGNED) {
                printf("An already signed shortcut was passed into -i; did you mean to use the resign command instead?\n");
                return 0;
            }
        }
        size_t authDataSize = 0;
        uint8_t *authData = load_binary(authDataPath, &authDataSize);
        if (!authData) {
            printf("Failed to load auth data.\n");
            return 0;
        }
        uint8_t *privateKey = load_binary(privateKeyPath, 0);
        if (!privateKey) {
            printf("Failed to load private key.\n");
            return 0;
        }
        
        size_t signedShortcutSize = 0;
        uint8_t *signedShortcut;
        if (rawAarFlag) {
            signedShortcut = sign_shortcut_aar_with_private_key_and_auth_data(unsignedPlist, unsignedPlistSize, privateKey, authData, authDataSize, &signedShortcutSize);
        } else {
            signedShortcut = sign_shortcut_with_private_key_and_auth_data(unsignedPlist, unsignedPlistSize, privateKey, authData, authDataSize, &signedShortcutSize);
        }
        if (!signedShortcut) {
            printf("Failed to resign shortcut with new plist.\n");
            return -1;
        }

        free(privateKey);
        free(authData);
        
        /* Copy signed shortcut to outputPath */
        FILE *fp = fopen(outputPath, "w");
        if (!fp) {
            free(signedShortcut);
            printf("Failed to open outputPath.\n");
            return -1;
        }
        fwrite(signedShortcut, signedShortcutSize, 1, fp);
        fclose(fp);
        free(signedShortcut);
    } else if (SS_CMD_INFO == ssCommand) {
        size_t signedShortcutSize;
        uint8_t *signedShortcut = load_binary(inputPath, &signedShortcutSize);
        if (!signedShortcut) {
            printf("Failed to load unsigned plist.\n");
            return 0;
        }
        print_shortcut_cert_info(signedShortcut, signedShortcutSize);
    }
    return 0;
}
