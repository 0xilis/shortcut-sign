#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include "../lib/libshortcutsign/extract.h"
#include "../lib/libshortcutsign/verify.h"
#include "apple_archive.h"

#define OPTSTR "i:o:u:k:hv"

typedef enum {
    SS_CMD_SIGN,
    SS_CMD_EXTRACT,
    SS_CMD_VERIFY,
    SS_CMD_AUTH_EXTRACT,
    SS_CMD_RESIGN,
    SS_CMD_VERSION,
} SSCommand;

void resign_shortcut_with_new_aa(uint8_t *aeaShortcutArchive, void *archivedDir, size_t aeaShortcutArchiveSize, const char *outputPath, void *privateKey);

void show_help(void) {
    printf("Usage: shortcut-sign command <options>\n\n");
    printf("Commands:\n\n");
    /* printf(" sign: sign an unsigned shortcut.\n"); */
    printf(" extract: extract unsigned shortcut from a signed shortcut.\n");
    printf(" verify: verify signature of signed shortcut. (currently only contact-signed)\n");
    printf(" auth: extract auth data of shortcut\n");
    printf(" resign: resign a signed shortcut\n");
    printf(" version: display version of shortcut-sign\n");
    printf("\n");
    printf("Options:\n\n");
    printf(" -i: path to the input file or directory.\n");
    printf(" -o: path to the output file or directory.\n");
    printf(" -u: optional option for resign command, for signing over shortcut with unsigned shortcut.\n");
    printf(" -k: for signing/resigning, specify file containing ASN1 private ECDSA-P256 key\n");
    printf(" -h: this ;-)\n");
    printf("\n");
}

uint8_t *load_binary(const char *signedShortcutPath) {
    /* load AEA archive into memory */
    FILE *fp = fopen(signedShortcutPath,"r");
    if (!fp) {
        fprintf(stderr,"shortcut-sign: load_binary could not open path\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    size_t binary_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *aeaShortcutArchive = malloc(binary_size * sizeof(char));
    /* copy bytes to binary, byte by byte... */
    int c;
    size_t n = 0;
    while ((c = fgetc(fp)) != EOF) {
        aeaShortcutArchive[n++] = (char) c;
    }
    fclose(fp);
    if (n != binary_size) {
        fprintf(stderr,"shortcut-sign: load_binary could not read entire file\n");
        free(aeaShortcutArchive);
        return 0;
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
    } else {
        printf("Invalid command.\n");
        show_help();
        return 0;
    }
    /* Hack to get getopt() to skip the command in argv */
    argv++;
    argc--;

    char *inputPath = NULL;
    char *outputPath = NULL;
    char *unsignedPath = NULL;
    char *privateKeyPath = NULL;
    
    /* Parse args */
    int opt;
    while ((opt = getopt(argc, (char* const *)argv, OPTSTR)) != EOF) {
        if (opt == 'i') {
            inputPath = optarg;
        } else if (opt == 'o') {
            outputPath = optarg;
        } else if (opt == 'u') {
            unsignedPath = optarg;
        } else if (opt == 'k') {
            privateKeyPath = optarg;
        } else if (opt == 'h') {
            /* Show help */
            show_help();
            return 0;
        }
    }

    /* SS_CMD_VERSION is the only command where inputPath is not needed */
    if (SS_CMD_VERSION == ssCommand) {
        printf("Pre-1.0 (Unfinished)\n");
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
        if (verify_contact_signed_shortcut(inputPath)) {
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
        size_t appleArchiveSize = 0;
        uint8_t *appleArchive;
        if (unsignedPath) {
            /* User specified unsigned shortcut to resign shortcut over */
            /* Form Apple Archive and then resign */
            appleArchive = create_shortcuts_apple_archive(unsignedPath, &appleArchiveSize);
            if (!appleArchive) {
                printf("Apple Archive creation failed.\n");
                return 0;
            }
        } else {
            /* Extract unsigned AA from AEA (i need to add this to libshortcutsign) */
            appleArchive = ext_aa_from_aea(inputPath, &appleArchiveSize);
            if (!appleArchive) {
                printf("Apple Archive extraction failed.\n");
                return 0;
            }
        }

        uint8_t *aeaShortcutArchive = load_binary(inputPath);
        if (!aeaShortcutArchive) {
            printf("Failed to load input AEA.\n");
            return 0;
        }
        uint8_t *privateKey = load_binary(privateKeyPath);
        if (!privateKey) {
            printf("Failed to load private key.\n");
            return 0;
        }
        resign_shortcut_with_new_aa(aeaShortcutArchive, appleArchive, appleArchiveSize, outputPath, privateKey);
        /* resign_shortcut_with_new_aa auto frees aeaShortcutArchive & appleArchive so we don't free it */
        free(privateKey);
    }
    return 0;
}