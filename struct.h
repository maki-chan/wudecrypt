#ifndef _STRUCT_H_
#define _STRUCT_H_
#include "config.h"
#include "utarray.h"

struct partition_cluster {
    uint64_t offset;
    uint64_t size;

    uint32_t unknown1;
    uint32_t unknown2;
};

struct partition_entry {
        uint8_t is_directory;
        uint64_t name_offset;
        // Allow names with a size of up to 512 bytes, should be enough hopefully
        char entry_name[512];

        uint64_t offset_in_cluster;

        uint32_t last_row_in_dir;
        uint64_t size;

        uint16_t unknown;
        uint16_t starting_cluster;
};

static const UT_icd partition_entry_icd = { sizeof(struct partition_entry), NULL, NULL, NULL };

struct partition {
    uint64_t offset;
    uint8_t identifier[25];
    char name[PTOC_SIZE];

    uint8_t key[16];
    uint8_t iv[16];

    uint32_t cluster_count;
    struct partition_cluster* clusters;

    UT_array* entries;
};

struct titlekey {
    char name[18];
    uint8_t encryptedKey[16];
    uint8_t decryptedKey[16];
    uint8_t iv[16];
};

static const UT_icd titlekey_icd = { sizeof(struct titlekey), NULL, NULL, NULL };

struct block {
    int64_t number;
    int64_t offset;
};
#endif // _STRUCT_H_
