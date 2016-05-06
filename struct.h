#ifndef _STRUCT_H_
#define _STRUCT_H_
#include "config.h"

struct clusters {
    uint64_t offset;
    uint64_t size;

    uint32_t unknown1;
    uint32_t unknown2;
};

struct partition_entry {
        uint8_t is_directory;
        uint64_t name_offset;
        char* entry_name;

        uint64_t offset_in_cluster;

        uint32_t last_row_in_dir;
        uint64_t size;

        uint16_t unknown;
        uint16_t starting_cluster;
};

struct partition {
    uint64_t offset;
    uint8_t identifier[25];
    char name[PTOC_SIZE];

    uint8_t key[16];
    uint8_t iv[16];

    uint32_t cluster_count;
    struct cluster* clusters;

    struct partition_entry* entries;
};
#endif // _STRUCT_H_
