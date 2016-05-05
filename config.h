#ifndef CONFIG_H
#define CONFIG_H
#include <stdint.h>

static const char* APP_VERSION = "0.1";

static const size_t KEY_LENGTH = 16;
static const size_t GAME_SERIAL_LENGTH = 10;
static const size_t GAME_VER_LENGTH = 2;
static const size_t SYS_VER_LENGTH = 3;
static const size_t REGION_LENGTH = 3;

static const uint8_t MAGIC_BYTES[4] = { 0x57, 0x55, 0x50, 0x2D };

static const unsigned long long int WIIU_DECRYPTED_AREA_OFFSET = 0x18000;
static const unsigned long int PARTITION_TOC_OFFSET = 0x800;
static const unsigned long int PARTITION_TOC_ENTRY_SIZE = 0x80;

static const uint8_t DECRYPTED_AREA_SIGNATURE[4] = { 0xCC, 0xA6, 0xE6, 0x7B };
static const uint8_t PARTITION_FILE_TABLE_SIGNATURE[4] = { 0x46, 0x53, 0x54, 0x00 };

static const char* TITLE_TICKET_FILE = "TITLE.TIK";
#endif
