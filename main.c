#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "uthash.h"
#include "utarray.h"
#include "struct.h"
#include "functions.h"
#include "aes.h"

int main(int argc, char* argv[]) {
    int i, j, c;
    uint32_t partition_count, current_ft_size;
    uint64_t cluster_start, entries_offset, total_entries, name_table_offset, current_entry_offset, current_name_offset;
    char* gameserial;
    char* gameversion;
    char* gameregion;
    char* sysversion;
    char partition_hash_name[18];
    uint8_t* commonkey;
    uint8_t* disckey;
    uint8_t* partition_toc;
    uint8_t* partition_block;
    uint8_t raw_entry[16];
    struct partition_entry* entry;
    struct partition* partitions;
    struct titlekeystruct* titlekey;
    struct keydic* titlekeys = NULL;
    FILE* wudimage;

    printf("WUDecrypt v%s by makikatze\n", APP_VERSION);
    printf("Licensed under GNU AGPLv3\n\n");

    if (argc != 5) {
        printf("Usage: %s <disc.wud> <outputdir> <commonkey.bin> <disckey.bin>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    commonkey = loadKey(argv[3]);
    if (commonkey == NULL) {
        fprintf(stderr, "Error while loading common key\n");
        exit(EXIT_FAILURE);
    }

    disckey = loadKey(argv[4]);
    if (disckey == NULL) {
        fprintf(stderr, "Error while loading disc key\n");
        exit(EXIT_FAILURE);
    }

    wudimage = fopen(argv[1], "r");
    if (wudimage == NULL) {
        fprintf(stderr, "Could not open WUD image\n");
        exit(EXIT_FAILURE);
    }

    gameserial = (char*)readFileOffset(0, sizeof(char), GAME_SERIAL_LENGTH, wudimage);
    if (gameserial == NULL) {
        fprintf(stderr, "Couldn't read game serial from image\n");
        fclose(wudimage);
        exit(EXIT_FAILURE);
    }
    if (memcmp(gameserial, MAGIC_BYTES, 4) != 0) {
        fprintf(stderr, "WARNING: Most probably no valid WUD image\nTrying to continue anyways, although errors are expected!\n\n");
    }

    fseek(wudimage, 1, SEEK_CUR);
    gameversion = (char*)readFile(sizeof(char), GAME_VER_LENGTH, wudimage);
    if (gameversion == NULL) {
        fprintf(stderr, "Couldn't read game version from image\n");
        fclose(wudimage);
        exit(EXIT_FAILURE);
    }

    fseek(wudimage, 1, SEEK_CUR);
    sysversion = (char*)readFile(sizeof(char), SYS_VER_LENGTH, wudimage);
    if (sysversion == NULL) {
        fprintf(stderr, "Couldn't read system version from image\n");
        fclose(wudimage);
        exit(EXIT_FAILURE);
    }
    gameregion = (char*)readFile(sizeof(char), REGION_LENGTH, wudimage);
    if (gameregion == NULL) {
        fprintf(stderr, "Couldn't read game region from image\n");
        fclose(wudimage);
        exit(EXIT_FAILURE);
    }

    // Print information about game
    printf("Game Serial:    %.*s\n", (int)GAME_SERIAL_LENGTH, gameserial);
    printf("Game Revision:  %.*s\n", (int)GAME_VER_LENGTH, gameversion);
    printf("System Version: %c.%c.%c\n", sysversion[0], sysversion[1], sysversion[2]);
    printf("Game Region:    %.*s\n\n", (int)REGION_LENGTH, gameregion);

    partition_toc = readEncryptedOffset(disckey, WIIU_DECRYPTED_AREA_OFFSET, 0x8000, wudimage);
    if (partition_toc == NULL || memcmp(partition_toc, DECRYPTED_AREA_SIGNATURE, 4) != 0) {
        fprintf(stderr, "Couldn't decrypt partition table\n");
        fclose(wudimage);
        exit(EXIT_FAILURE);
    }

    partition_count = bytesToUIntBE(partition_toc + 0x1C);
    printf("Partition count: %d\n\n", partition_count);

    partitions = (struct partition*)malloc(partition_count * sizeof(struct partition));
    for (i = 0; i < partition_count; i++) {
        memcpy(partitions[i].identifier, partition_toc + PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE), 0x19);
        memcpy(partitions[i].name, partition_toc + PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE), PARTITION_TOC_ENTRY_SIZE);
        partitions[i].offset = (uint64_t)bytesToUIntBE(partition_toc + PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE) + 0x20);
        partitions[i].offset *= 0x8000;
        partitions[i].offset -= 0x10000;

        printf("Partition %d:\n", i + 1);
        printf("\tPartition ID:     %.*s\n", 0x19, partitions[i].identifier);
        printf("\tPartition Name:   %s\n", partitions[i].name);
        printf("\tPartition Offset: 0x%llX\n", (unsigned long long int)partitions[i].offset);

        strncpy(partition_hash_name, partitions[i].name, 18);
        HASH_FIND_STR(titlekeys, partition_hash_name, titlekey);
        if (strncmp((char*)partitions[i].name, "SI", 2) == 0
            || strncmp((char*)partitions[i].name, "UP", 2) == 0
            || strncmp((char*)partitions[i].name, "GI", 2) == 0
            || titlekey != NULL) {
            if (titlekey == NULL) {
                memcpy(partitions[i].key, disckey, 16);
                memset(partitions[i].iv, 0, 16);
            } else {
                memcpy(partitions[i].key, titlekey->decryptedKey, 16);
                memcpy(partitions[i].iv, titlekey->iv, 16);
            }

            printf("\tPartition Key:    ");
            for (c = 0; c < 16; c++) {
                printf("%02X", partitions[i].key[c]);
            }
            printf("\n\n");

            current_ft_size = 0x8000;

            partition_block = readEncryptedOffset(partitions[i].key, WIIU_DECRYPTED_AREA_OFFSET + partitions[i].offset, current_ft_size, wudimage);

            if (memcmp(partition_block, PARTITION_FILE_TABLE_SIGNATURE, 4) != 0) {
                fprintf(stderr, "Decrypted partition %s has no valid file table signature\n", partitions[i].name);
                fclose(wudimage);
                exit(EXIT_FAILURE);
            }

            partitions[i].cluster_count = bytesToUIntBE(partition_block + 8);
            partitions[i].clusters = (struct partition_cluster*)malloc(partitions[i].cluster_count * sizeof(struct partition_cluster));
            for (c = 0; c < partitions[i].cluster_count; c++) {
                cluster_start = (uint64_t)(bytesToUIntBE(partition_block + 0x20 + (0x20 * c))) * 0x8000;
                partitions[i].clusters[c].unknown1 = bytesToUIntBE(partition_block + 0x20 + (0x20 * c) + 0x10);
                partitions[i].clusters[c].unknown2 = bytesToUIntBE(partition_block + 0x20 + (0x20 * c) + 0x14);

                if (cluster_start > 0) {
                    partitions[i].clusters[c].offset = cluster_start - 0x8000;
                } else {
                    partitions[i].clusters[c].offset = 0;
                }

                partitions[i].clusters[c].size = (uint64_t)(bytesToUIntBE(partition_block + 0x20 + (0x20 * c) + 4)) * 0x8000;
            }

            entries_offset = (bytesToUIntBE(partition_block + 4) * bytesToUIntBE(partition_block + 8)) + 0x20;

            memcpy(raw_entry, partition_block + entries_offset, 16);
            entry = create_partition_entry(raw_entry);

            total_entries = entry->last_row_in_dir;
            name_table_offset = entries_offset + (total_entries * 0x10);

            strncpy(entry->entry_name, (char*)(partition_block + name_table_offset + entry->name_offset), 0x200);

            utarray_new(partitions[i].entries, &partition_entry_icd);
            utarray_push_back(partitions[i].entries, entry);

            for(j = 1; j < total_entries; j++) {
                current_entry_offset = entries_offset + (j * 0x10);

                while((current_entry_offset + 0x10) > current_ft_size) {
                    current_ft_size += 0x8000;
                    free(partition_block);
                    partition_block = readEncryptedOffset(partitions[i].key, WIIU_DECRYPTED_AREA_OFFSET + partitions[i].offset, current_ft_size, wudimage);
                }

                memcpy(raw_entry, partition_block + current_entry_offset, 16);
                entry = create_partition_entry(raw_entry);

                current_name_offset = name_table_offset + entry->name_offset;

                while((current_name_offset + 0x200) > current_ft_size) {
                    current_ft_size += 0x8000;
                    free(partition_block);
                    partition_block = readEncryptedOffset(partitions[i].key, WIIU_DECRYPTED_AREA_OFFSET + partitions[i].offset, current_ft_size, wudimage);
                }

                strncpy(entry->entry_name, (char*)(partition_block + current_name_offset), 0x200);

                utarray_push_back(partitions[i].entries, entry);
            }

            if (strncmp((char*)partitions[i].name, "SI", 2) == 0
                || strncmp((char*)partitions[i].name, "GI", 2) == 0) {
                for(entry = (struct partition_entry*)utarray_front(partitions[i].entries); entry != NULL; entry = (struct partition_entry*)utarray_next(partitions[i].entries, entry)) {
                    if(entry->is_directory != 1 && strincmp(entry->entry_name, TITLE_TICKET_FILE, strlen(TITLE_TICKET_FILE)) == 0) {
                        // TODO Add title key decryption here, function to decrypt exists now
                    }
                }
            }
        }
    }

    fclose(wudimage);
    return EXIT_SUCCESS;
}
