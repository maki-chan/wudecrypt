#ifndef _FUNCTIONS_H_
#define _FUNCTIONS_H_
#include <stdio.h>

uint8_t* loadKeyFile(FILE* file);
uint8_t* loadKey(char* filename);

void* readFileOffset(long int offset, size_t size, size_t count, FILE* file);
void* readFile(size_t size, size_t count, FILE* file);

uint8_t* readEncryptedOffset(uint8_t* key, long int offset, size_t size, FILE* file);

uint32_t bytesToUIntBE(uint8_t* bytes);
#endif // _FUNCTIONS_H_
