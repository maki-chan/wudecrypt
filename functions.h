#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_
#include <stdio.h>
#include "struct.h"

uint8_t* loadKeyFile(FILE* file);
uint8_t* loadKey(char* filename);

void* readFileOffset(uint64_t offset, size_t size, size_t count, FILE* file);
void* readFile(size_t size, size_t count, FILE* file);

uint8_t* readEncryptedOffset(uint8_t* key, uint64_t offset, size_t size, FILE* file);
uint8_t* readVolumeEncryptedOffset(uint8_t* key, int64_t volume_offset, int64_t cluster_offset, int64_t file_offset, size_t size, FILE* file);

struct partition_entry* create_partition_entry(uint8_t* raw_entry);

int strincmp(const char *s1, const char *s2, int n);

uint16_t bytesToUShortBE(uint8_t* bytes);
uint32_t bytesToUIntBE(uint8_t* bytes);
#endif // _FUNCTIONS_H_
