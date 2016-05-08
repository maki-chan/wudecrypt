#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "struct.h"
#include "functions.h"
#include "aes.h"
#include "sha1.h"

uint8_t* loadKeyFile(FILE* file) {
    uint8_t* key;

    // Check for errors with the given file pointer
    if (file == NULL) {
        fprintf(stderr, "Given file pointer was a null reference\n");
        return NULL;
    }

    // Allocate the memory where we'll store the key
    key = (uint8_t*)malloc(KEY_LENGTH * sizeof(uint8_t));
    if (key == NULL) {
        fprintf(stderr, "Could not allocate enough bytes for key\n");
        return NULL;
    }

    // Read the key from the given file
    if (fread(key, sizeof(uint8_t), KEY_LENGTH, file) != KEY_LENGTH) {
        free(key);
        fprintf(stderr, "Could not read the key from file\n");
        return NULL;
    }

    return key;
}

uint8_t* loadKey(char* filename) {
    FILE* file;
    uint8_t* key = NULL;

    file = fopen(filename, "r");
    if (file != NULL) {
        key = loadKeyFile(file);
        fclose(file);
    }

    return key;
}

void* readFileOffset(uint64_t offset, size_t size, size_t count, FILE* file) {
    void* output;
    if (fseek(file, offset, SEEK_SET) != 0) {
        fprintf(stderr, "Error while seeking in file\n");
        return NULL;
    }
    output = malloc(size * count);
    if (output == NULL) {
        fprintf(stderr, "Could not allocate enough bytes to read into memory\n");
        return NULL;
    }
    if (fread(output, size, count, file) != count) {
        fprintf(stderr, "WARNING: Could not read as many bytes as requested from file\n");
    }
    return output;
}

void* readFile(size_t size, size_t count, FILE* file) {
    void* output;
    output = malloc(size * count);
    if (output == NULL) {
        fprintf(stderr, "Could not allocate enough bytes to read into memory\n");
        return NULL;
    }
    if (fread(output, size, count, file) != count) {
        fprintf(stderr, "WARNING: Could not read as many bytes as requested from file\n");
    }
    return output;
}

uint8_t* readEncryptedOffset(uint8_t* key, uint64_t offset, size_t count, FILE* file) {
    uint8_t iv[16];
    uint8_t* encrypted_chunk = (uint8_t*)readFileOffset(offset, sizeof(uint8_t), count, file);
    uint8_t* decrypted_chunk;
    if (encrypted_chunk == NULL) {
        fprintf(stderr, "Could not read encrypted chunk from file\n");
        return NULL;
    }
    decrypted_chunk = (uint8_t*)malloc(count * sizeof(uint8_t));
    if (decrypted_chunk == NULL) {
        fprintf(stderr, "Could not allocate enough memory to decrypt chunk\n");
        free(encrypted_chunk);
        return NULL;
    }

    memset(iv, 0, 16);
    AES128_CBC_decrypt_buffer(decrypted_chunk, encrypted_chunk, count, key, iv);

    free(encrypted_chunk);
    return decrypted_chunk;
}

uint8_t* readVolumeEncryptedOffset(uint8_t* key, int64_t volume_offset, int64_t cluster_offset, int64_t file_offset, size_t size, FILE* file) {
    uint8_t iv[16];
    uint8_t* encrypted_chunk;
    uint8_t* decrypted_chunk;
    uint8_t* output = (uint8_t*)malloc(size * sizeof(uint8_t));
    int64_t buffer_location = 0;
    int64_t max_copy_size, copy_size, read_offset;
    struct block blockstruct;

    while (size > 0) {
        blockstruct.number = file_offset / 0x8000;
        blockstruct.offset = file_offset % 0x8000;

        read_offset = WIIU_DECRYPTED_AREA_OFFSET + volume_offset + cluster_offset + (blockstruct.number * 0x8000);
        encrypted_chunk = (uint8_t*)readFileOffset(read_offset, sizeof(uint8_t), 0x8000, file);
        if (encrypted_chunk == NULL) {
            fprintf(stderr, "Could not read encrypted chunk from file\n");
            return NULL;
        }

        decrypted_chunk = (uint8_t*)malloc(0x8000 * sizeof(uint8_t));
        if (decrypted_chunk == NULL) {
            fprintf(stderr, "Could not allocate enough memory to decrypt chunk\n");
            free(encrypted_chunk);
            return NULL;
        }

        memset(iv, 0, 16);
        AES128_CBC_decrypt_buffer(decrypted_chunk, encrypted_chunk, 0x8000, key, iv);
        free(encrypted_chunk);

        max_copy_size = 0x8000 - blockstruct.offset;
        copy_size = (size > max_copy_size) ? max_copy_size : size;

        memcpy(output + buffer_location, decrypted_chunk + blockstruct.offset, copy_size);
        free(decrypted_chunk);

        size -= copy_size;
        buffer_location += copy_size;
        file_offset += copy_size;
    }

    return output;
}

struct partition_entry* create_partition_entry(uint8_t* raw_entry) {
    struct partition_entry* entry = (struct partition_entry*)malloc(sizeof(struct partition_entry));

    if(raw_entry[0] == 1) {
        entry->is_directory = 1;
        entry->last_row_in_dir = bytesToUIntBE(raw_entry + 8);
    } else {
        entry->is_directory = 0;
        entry->size = bytesToUIntBE(raw_entry + 8);
    }

    entry->name_offset = bytesToUIntBE(raw_entry) & 0x00FFFFFF;

    entry->offset_in_cluster = (uint64_t)bytesToUIntBE(raw_entry + 4);
    entry->offset_in_cluster <<= 5;

    entry->unknown = bytesToUShortBE(raw_entry + 0x0C);
    entry->starting_cluster = bytesToUShortBE(raw_entry + 0x0E);

    return entry;
}

struct file* create_file(char* parent, char* filename, int64_t volume_base_offset, int64_t data_section_offset, int64_t lba, int64_t size, struct partition* source_partition, uint32_t entry_id) {
    struct file* file = (struct file*)malloc(sizeof(struct file));

    strncpy(file->parent, parent, 512);
    strncpy(file->filename, filename, 512);
    file->volume_base_offset = volume_base_offset;
    file->data_section_offset = data_section_offset;
    file->lba = lba;
    file->size = size;
    file->parent_partition = source_partition;
    file->entry_id = entry_id;

    return file;
}

struct directory* create_directory(struct partition* source_partition, uint32_t* current_index, char* parent) {
    struct directory* dir = (struct directory*)malloc(sizeof(struct directory));
    struct partition_entry* entry;
    struct directory* subdir;
    struct file* file;
    char next_dir[512];
    uint32_t last_row_in_dir;

    utarray_new(dir->subdirs, &directory_icd);
    utarray_new(dir->files, &file_icd);

    if (strlen(parent) == 0) {
        strncpy(dir->parent, source_partition->name, PARTITION_TOC_ENTRY_SIZE);
    } else {
        strncpy(dir->parent, parent, 512);
    }

    strncpy(dir->directory_name, ((struct partition_entry*)utarray_eltptr(source_partition->entries, *current_index))->entry_name, 512);
    if (dir->parent[strlen(dir->parent) - 1] != '/') {
        sprintf(next_dir, "%s/%s", dir->parent, dir->directory_name);
    } else {
        sprintf(next_dir, "%s%s", dir->parent, dir->directory_name);
    }

    last_row_in_dir = ((struct partition_entry*)utarray_eltptr(source_partition->entries, *current_index))->last_row_in_dir;
    for (++(*current_index); *current_index < last_row_in_dir; (*current_index)++) {
        if (((struct partition_entry*)utarray_eltptr(source_partition->entries, *current_index))->is_directory) {
            subdir = create_directory(source_partition, current_index, next_dir);
            utarray_push_back(dir->subdirs, subdir);
            (*current_index)--;
        } else {
            entry = (struct partition_entry*)utarray_eltptr(source_partition->entries, *current_index);
            file = create_file(next_dir, entry->entry_name, source_partition->offset, source_partition->clusters[entry->starting_cluster].offset, entry->offset_in_cluster, entry->size, source_partition, *current_index);
            utarray_push_back(dir->files, file);
        }
    }

    return dir;
}

void extract_all(FILE* infile, struct directory* root_directory, char* outputdir) {
    if (makedir(outputdir) != 0) {
        if (errno != EEXIST) {
            printf("Error: Output directory does not exist, cannot continue\n");
            return;
        }
    }

    extract_dir(infile, root_directory, outputdir);
}

void extract_dir(FILE* infile, struct directory* dir, char* outputdir) {
    char fullout[1024];
    struct directory* subdir;
    struct file* file;

    sprintf(fullout, "%s/%s/%s", outputdir, dir->parent, dir->directory_name);

    if (makedir(fullout) != 0) {
        if (errno != EEXIST) {
            printf("Error: Could not create the following directory, cannot continue\n");
            printf("%s\n", fullout);
            return;
        }
    }

    for (file = (struct file*)utarray_front(dir->files); file != NULL; file = (struct file*)utarray_next(dir->files, file)) {
        extract_file(infile, file, outputdir);
    }
    for (subdir = (struct directory*)utarray_front(dir->subdirs); subdir != NULL; subdir = (struct directory*)utarray_next(dir->subdirs, subdir)) {
        extract_dir(infile, subdir, outputdir);
    }
}

void extract_file(FILE* infile, struct file* file, char* outputdir) {
    char fullout[1024];
    uint8_t first_iv[16];
    uint8_t* cluster_id;
    struct partition_entry* entry;

    sprintf(fullout, "%s/%s/%s", outputdir, file->parent, file->filename);
    printf("%s\n", fullout);

    memset(first_iv, 0, 16);
    entry = (struct partition_entry*)utarray_eltptr(file->parent_partition->entries, file->entry_id);
    cluster_id = (uint8_t*)(&(entry->starting_cluster));
    first_iv[0] = cluster_id[1];
    first_iv[1] = cluster_id[0];

    if (entry->unknown == 0x0400
        || entry->unknown == 0x0040
        || (file->parent_partition->clusters[entry->starting_cluster].unknown1 == 0x00000400
            && file->parent_partition->clusters[entry->starting_cluster].unknown2 == 0x02000000)) {
        extract_file_hashed(infile, fullout, file->parent_partition->name, file->volume_base_offset, file->data_section_offset, file->lba, file->size, file->parent_partition->key, first_iv, entry->starting_cluster);
    } else {
        extract_file_unhashed(infile, fullout, file->parent_partition->name, file->volume_base_offset, file->data_section_offset, file->lba, file->size, file->parent_partition->key, first_iv);
    }
}

void extract_file_hashed(FILE* infile, char* outputpath, char* volumename, int64_t volume_offset, int64_t cluster_offset, int64_t file_offset, int64_t size, uint8_t* key, uint8_t* iv, uint16_t cluster_id) {
    uint8_t* encrypted_cluster;
    uint8_t* decrypted_header;
    uint8_t* decrypted_cluster;
    uint8_t cluster_iv[16];
    uint8_t h0[0x14];
    uint8_t block_sha1[0x14];
    int64_t max_copy_size;
    int64_t copy_size;
    int64_t read_offset = 0;
    int64_t block_size = 0xFC00;
    int64_t iv_block = 0;
    struct block blockstruct;
    FILE* outfile;

    memset(block_sha1, 0, 0x14);

    outfile = fopen(outputpath, "w");
    if (outfile == NULL) {
        printf("Error: Cannot write output file, wasn't able to open it\n");
        printf("Error for \"%s\"", outputpath);
        return;
    }

    decrypted_header = (uint8_t*)malloc(0x400 * sizeof(uint8_t));
    decrypted_cluster = (uint8_t*)malloc(block_size * sizeof(uint8_t));
    while (size > 0) {
        blockstruct.number = file_offset / block_size;
        blockstruct.offset = file_offset % block_size;

        if(blockstruct.offset != (file_offset - (file_offset / block_size * block_size))) {
            blockstruct.offset = file_offset - (file_offset / block_size * block_size);
        }

        iv_block = blockstruct.number & 0xF;
        iv_block = iv_block > 0x10 ? 0 : iv_block;

        read_offset = WIIU_DECRYPTED_AREA_OFFSET + volume_offset + cluster_offset + (blockstruct.number * 0x10000);

        encrypted_cluster = readFileOffset(read_offset, sizeof(uint8_t), 0x400, infile);
        AES128_CBC_decrypt_buffer(decrypted_header, encrypted_cluster, 0x400, key, iv);
        free(encrypted_cluster);

        memcpy(cluster_iv, decrypted_header + (iv_block * 0x14), 16);
        memcpy(h0, decrypted_header + (iv_block * 0x14), 0x14);

        if (iv_block == 0) {
            cluster_iv[1] ^= (uint8_t)cluster_id;
        }

        encrypted_cluster = readFileOffset(read_offset + 0x400, sizeof(uint8_t), block_size, infile);
        AES128_CBC_decrypt_buffer(decrypted_cluster, encrypted_cluster, block_size, key, cluster_iv);
        free(encrypted_cluster);

        mbedtls_sha1(decrypted_cluster, block_size, block_sha1);
        if (iv_block == 0) {
            block_sha1[1] ^= (uint8_t)cluster_id;
        }

        if (memcmp(block_sha1, h0, 0x14) != 0) {
            printf("Warning: Failed SHA1 checksum verification for %s\n", outputpath);
        }

        max_copy_size = block_size - blockstruct.offset;
        copy_size = (size > max_copy_size) ? max_copy_size : size;
        if (fwrite(decrypted_cluster + blockstruct.offset, sizeof(uint8_t), copy_size, outfile) != copy_size) {
            printf("Warning: Couldn't write expected output for %s\n", outputpath);
        }

        size -= copy_size;
        file_offset += copy_size;
    }
    free(decrypted_header);
    free(decrypted_cluster);

    fclose(outfile);
}

void extract_file_unhashed(FILE* infile, char* outputpath, char* volumename, int64_t volume_offset, int64_t cluster_offset, int64_t file_offset, int64_t size, uint8_t* key, uint8_t* iv) {
    uint8_t* encrypted_cluster;
    uint8_t* decrypted_cluster;
    int64_t max_copy_size;
    int64_t copy_size;
    int64_t read_offset = 0;
    struct block blockstruct;
    FILE* outfile;

    outfile = fopen(outputpath, "w");
    if (outfile == NULL) {
        printf("Error: Cannot write output file, wasn't able to open it\n");
        printf("Error for \"%s\"", outputpath);
        return;
    }

    decrypted_cluster = (uint8_t*)malloc(0x8000 * sizeof(uint8_t));
    while (size > 0) {
        blockstruct.number = file_offset / 0x8000;
        blockstruct.offset = file_offset % 0x8000;

        read_offset = WIIU_DECRYPTED_AREA_OFFSET + volume_offset + cluster_offset + (blockstruct.number * 0x8000);

        encrypted_cluster = readFileOffset(read_offset, sizeof(uint8_t), 0x8000, infile);
        AES128_CBC_decrypt_buffer(decrypted_cluster, encrypted_cluster, 0x8000, key, iv);
        free(encrypted_cluster);

        max_copy_size = 0x8000 - blockstruct.offset;
        copy_size = (size > max_copy_size) ? max_copy_size : size;
        if (fwrite(decrypted_cluster + blockstruct.offset, sizeof(uint8_t), copy_size, outfile) != copy_size) {
            printf("Warning: Couldn't write expected output for\n%s\n", outputpath);
        }


        size -= copy_size;
        file_offset += copy_size;
    }
    free(decrypted_cluster);

    fclose(outfile);
}

int strincmp(const char *s1, const char *s2, int n)
{
	/* case insensitive comparison */
	int d;
	while (--n >= 0) {
	  d = (tolower(*s1) - tolower(*s2));
	  if ( d != 0 || *s1 == '\0' || *s2 == '\0' )
	    return d;
	  ++s1;
	  ++s2;
	}
	return 0;
}

int titlekeycmp(const void* e1, const void* e2) {
    const struct titlekey* ele1 = (struct titlekey*)e1;
    const struct titlekey* ele2 = (struct titlekey*)e2;
    return strncmp(ele1->name, ele2->name, 18);
}

uint16_t bytesToUShortBE(uint8_t* bytes) {
    return (bytes[0] << 8) | bytes[1];
}

uint32_t bytesToUIntBE(uint8_t* bytes) {
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}
