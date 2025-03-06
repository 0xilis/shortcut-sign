//
//  libqmc.h
//  QuickMerge Helper
//
//  Created by Snoolie Keffaber on 2024/03/13.
//

#ifndef libqmc_h
#define libqmc_h

#include <stdio.h>
#include <inttypes.h>

/* qmc types */
typedef enum QmcType_t {
    QMC_RAW,
    QMC_OPTIMIZED,
    QMC_RAW_FLIP,
    QMC_OPTIMIZED_FLIP,
    QMC_WARP, /* QMC_WARP is just a QMC_OPTIMIZED_FLIP file but compressed again after */
} QmcType;

uint8_t *signing_private_key_for_raw_qmd(const char *path);
uint8_t *signing_private_key_for_raw_qmd_bitflip(const char *path, unsigned long long bitflip, unsigned long sizekey);
uint8_t *signing_auth_data_for_raw_qmd(const char *path);
uint8_t *signing_private_key_for_qmc_path(const char *qmcPath);
uint8_t *signing_auth_data_for_raw_qmd(const char *path);
uint8_t *signing_private_key_for_qmc_path(const char *qmcPath);
uint8_t *raw_qmd_for_private_key_and_auth_data(uint8_t *privateKey, uint8_t *authData);
void create_qmc_at_path_for_raw_qmd(NSString *path, uint8_t *qmd, size_t qmd_size);

#endif /* libqmc_h */
