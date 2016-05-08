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
struct file* create_file(char* parent, char* filename, int64_t volume_base_offset, int64_t data_section_offset, int64_t lba, int64_t size, struct partition* source_partition, uint32_t entry_id);
struct directory* create_directory(struct partition* source_partition, uint32_t* current_index, char* parent);

void extract_all(FILE* infile, struct directory* root_directory, char* outputdir);
void extract_dir(FILE* infile, struct directory* dir, char* outputdir);
void extract_file(FILE* infile, struct file* file, char* outputdir);

void extract_file_hashed(FILE* infile, char* outputpath, char* volumename, int64_t volume_offset, int64_t cluster_offset, int64_t file_offset, int64_t size, uint8_t* key, uint8_t* iv, uint16_t cluster_id);
void extract_file_unhashed(FILE* infile, char* outputpath, char* volumename, int64_t volume_offset, int64_t cluster_offset, int64_t file_offset, int64_t size, uint8_t* key, uint8_t* iv);

int strincmp(const char* s1, const char* s2, int n);
int titlekeycmp(const void* e1, const void* e2);

uint16_t bytesToUShortBE(uint8_t* bytes);
uint32_t bytesToUIntBE(uint8_t* bytes);
#endif // _FUNCTIONS_H_
