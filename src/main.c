#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include "../lib/libshortcutsign/xplat.h"

#define OPTSTR "i:o:a:p:hv"

typedef enum {
    SS_CMD_SIGN,
    SS_CMD_EXTRACT,
    SS_CMD_VERIFY,
    SS_CMD_AUTH_EXTRACT,
    SS_CMD_RESIGN,
    SS_CMD_VERSION,
} SSCommand;

void show_help(void) {
    printf("Usage: shortcut-sign command <options>\n\n");
    printf("Commands:\n\n");
    /* printf(" sign: sign an unsigned shortcut.\n"); */
    printf(" extract: extract unsigned shortcut from a signed shortcut.\n");
    /* printf(" verify: verify signature of signed shortcut.\n"); */
    printf(" auth: extract auth data of shortcut\n");
    printf(" resign: resign a signed shortcut\n");
    printf(" version: display version of shortcut-sign\n");
    printf("\n");
    printf("Options:\n\n");
    printf(" -i: path to the input file or directory.\n");
    printf(" -o: path to the output file or directory.\n");
    printf(" -h: this ;-)\n");
    printf("\n");
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
    
    /* Parse args */
    int opt;
    while ((opt = getopt(argc, (char* const *)argv, OPTSTR)) != EOF) {
        if (opt == 'i') {
            inputPath = optarg;
        } else if (opt == 'o') {
            outputPath = optarg;
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
        extract_signed_shortcut(inputPath, outputPath);
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
    }
    return 0;
}