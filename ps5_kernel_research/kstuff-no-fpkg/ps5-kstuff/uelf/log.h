#pragma once
#include <stdint.h>
#include <sys/types.h>
#include <stdarg.h>

#define LOG(msg) uelf_write_log(msg, sizeof(msg))
#define printf(...) uelf_write_logf(__VA_ARGS__)
    
void log_word(uint64_t word);
void uelf_write_log(const char* data, size_t sz);
int puts(const char *str);
void uelf_write_logf(const char* format, ...);