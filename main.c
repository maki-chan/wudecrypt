#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "struct.h"
#include "functions.h"
#include "aes.h"

int main(int argc, char* argv[]) {
    int i;
    uint32_t partition_count;
    char* gameserial;
    char* gameversion;
    char* gameregion;
    char* sysversion;
    uint8_t* commonkey;
    uint8_t* disckey;
    uint8_t* partition_toc;
    struct partition* partitions;
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
    if (partition_toc == NULL) {
        fprintf(stderr, "Couldn't decrypt partition table\n");
        fclose(wudimage);
        exit(EXIT_FAILURE);
    }

    partition_count = bytesToUIntBE(partition_toc + 0x1C);
    printf("Partition count: %d\n\n", partition_count);

    partitions = (struct partition*)malloc(partition_count * sizeof(struct partition));
    for(i = 0; i < partition_count; i++) {
        memcpy(partitions[i].identifier, partition_toc + PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE), 0x19);
        memcpy(partitions[i].name, partition_toc + PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE), PARTITION_TOC_ENTRY_SIZE);
        partitions[i].offset = (uint64_t)bytesToUIntBE(partition_toc + PARTITION_TOC_OFFSET + (i * PARTITION_TOC_ENTRY_SIZE) + 0x20);
        partitions[i].offset *= 0x8000;
        partitions[i].offset -= 0x10000;

        printf("Partition %d:\n", i + 1);
        printf("\tPartition ID:     %.*s\n", 0x19, partitions[i].identifier);
        printf("\tPartition Name:   %s\n", partitions[i].name);
        printf("\tPartition Offset: 0x%llX\n\n", (unsigned long long int)partitions[i].offset);
    }

    fclose(wudimage);
    return EXIT_SUCCESS;
}
