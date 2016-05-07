#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "functions.h"
#include "aes.h"

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

void* readFileOffset(long int offset, size_t size, size_t count, FILE* file) {
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

uint8_t* readEncryptedOffset(uint8_t* key, long int offset, size_t count, FILE* file) {
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

uint16_t bytesToUShortBE(uint8_t* bytes) {
    return (bytes[0] << 8) | bytes[1];
}

uint32_t bytesToUIntBE(uint8_t* bytes) {
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}
