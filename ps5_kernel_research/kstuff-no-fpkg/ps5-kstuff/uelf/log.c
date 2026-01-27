#include "log.h"
#include "shared_area.h"
#include "utils.h"

uint64_t log[512];
uint64_t* p_log = log;

void log_word(uint64_t word)
{
    if(p_log != log + sizeof(log) / sizeof(*log))
        *p_log++ = word;
}

extern char uelf_log_buffer_kptr[];
extern char uelf_log_buffer_size[];
extern char uelf_log_buffer_pos_kptr[];

void uelf_write_log(const char* data, size_t sz)
{
    if (!data || sz == 0 || sz > (uint64_t)uelf_log_buffer_size) { return; }

    while(__atomic_test_and_set(&shared_area.uelf_log_lock, __ATOMIC_ACQUIRE)) {}

    uint64_t current_pos = kpeek64((uint64_t)uelf_log_buffer_pos_kptr);    
    uint64_t space_at_end = ((uint64_t)uelf_log_buffer_size) - current_pos;
    uint64_t first_chunk_sz = sz <= space_at_end ? sz : space_at_end;
    
    copy_to_kernel((uint64_t)uelf_log_buffer_kptr + current_pos, data, first_chunk_sz);
    if (first_chunk_sz < sz) 
    {
        copy_to_kernel((uint64_t)uelf_log_buffer_kptr, data + first_chunk_sz, sz - first_chunk_sz);
    }
    
    kpoke64((uint64_t)uelf_log_buffer_pos_kptr, (current_pos + sz) % ((uint64_t)uelf_log_buffer_size));
    __atomic_clear(&shared_area.uelf_log_lock, __ATOMIC_RELEASE);
}

void _putchar(char character)
{
    uelf_write_log(&character, 1);
}

int puts(const char *str)
{
    int len = 0;
    while(str[len])
        len++;
    ((char*)str)[len] = '\n';
    uelf_write_log(str, len + 1);
    ((char*)str)[len] = '\0';
    return len;
}

// Helper functions for uelf_write_logf
static size_t my_strlen(const char* s)
{
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void reverse_str(char* str, size_t len)
{
    size_t i = 0;
    size_t j = len - 1;
    while (i < j) {
        char temp = str[i];
        str[i] = str[j];
        str[j] = temp;
        i++;
        j--;
    }
}

static size_t utoa(uint64_t value, char* buffer, int base)
{
    size_t i = 0;

    if (value == 0) {
        buffer[i++] = '0';
        buffer[i] = '\0';
        return i;
    }

    while (value != 0) {
        uint64_t rem = value % base;
        buffer[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        value = value / base;
    }

    buffer[i] = '\0';
    reverse_str(buffer, i);
    return i;
}

static size_t itoa(int64_t value, char* buffer, int base)
{
    size_t i = 0;
    int is_negative = 0;

    if (value == 0) {
        buffer[i++] = '0';
        buffer[i] = '\0';
        return i;
    }

    if (value < 0 && base == 10) {
        is_negative = 1;
        value = -value;
    }

    while (value != 0) {
        int64_t rem = value % base;
        buffer[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        value = value / base;
    }

    if (is_negative) {
        buffer[i++] = '-';
    }

    buffer[i] = '\0';
    reverse_str(buffer, i);
    return i;
}

void uelf_write_logf(const char* format, ...)
{
    va_list args;
    va_start(args, format);

    char buffer[1024];
    size_t buf_pos = 0;

    for (size_t i = 0; format[i] != '\0'; i++) {
        if (format[i] != '%') {
            buffer[buf_pos++] = format[i];
            if (buf_pos >= sizeof(buffer) - 1) {
                uelf_write_log(buffer, buf_pos);
                buf_pos = 0;
            }
            continue;
        }

        i++; // Move past '%'

        // Handle format specifiers
        if (format[i] == '%') {
            buffer[buf_pos++] = '%';
        }
        else if (format[i] == 'c') {
            char c = (char)va_arg(args, int);
            buffer[buf_pos++] = c;
        }
        else if (format[i] == 's') {
            const char* s = va_arg(args, const char*);
            if (!s) s = "(null)";
            size_t len = my_strlen(s);

            // Flush current buffer if needed
            if (buf_pos > 0) {
                uelf_write_log(buffer, buf_pos);
                buf_pos = 0;
            }

            uelf_write_log(s, len);
        }
        else if (format[i] == 'd' || format[i] == 'i') {
            int64_t val = va_arg(args, int);
            char num_buf[32];
            size_t num_len = itoa(val, num_buf, 10);

            for (size_t j = 0; j < num_len; j++) {
                buffer[buf_pos++] = num_buf[j];
                if (buf_pos >= sizeof(buffer) - 1) {
                    uelf_write_log(buffer, buf_pos);
                    buf_pos = 0;
                }
            }
        }
        else if (format[i] == 'u') {
            uint64_t val = va_arg(args, unsigned int);
            char num_buf[32];
            size_t num_len = utoa(val, num_buf, 10);

            for (size_t j = 0; j < num_len; j++) {
                buffer[buf_pos++] = num_buf[j];
                if (buf_pos >= sizeof(buffer) - 1) {
                    uelf_write_log(buffer, buf_pos);
                    buf_pos = 0;
                }
            }
        }
        else if (format[i] == 'x' || format[i] == 'X') {
            uint64_t val = va_arg(args, unsigned int);
            char num_buf[32];
            size_t num_len = utoa(val, num_buf, 16);

            if (format[i] == 'X') {
                for (size_t j = 0; j < num_len; j++) {
                    if (num_buf[j] >= 'a' && num_buf[j] <= 'f') {
                        num_buf[j] = num_buf[j] - 'a' + 'A';
                    }
                }
            }

            for (size_t j = 0; j < num_len; j++) {
                buffer[buf_pos++] = num_buf[j];
                if (buf_pos >= sizeof(buffer) - 1) {
                    uelf_write_log(buffer, buf_pos);
                    buf_pos = 0;
                }
            }
        }
        else if (format[i] == 'p') {
            uint64_t val = (uint64_t)va_arg(args, void*);
            buffer[buf_pos++] = '0';
            buffer[buf_pos++] = 'x';

            char num_buf[32];
            size_t num_len = utoa(val, num_buf, 16);

            for (size_t j = 0; j < num_len; j++) {
                buffer[buf_pos++] = num_buf[j];
                if (buf_pos >= sizeof(buffer) - 1) {
                    uelf_write_log(buffer, buf_pos);
                    buf_pos = 0;
                }
            }
        }
        else if (format[i] == 'l') {
            // Handle long formats: %ld, %lu, %lx, %llx, etc.
            i++;
            int is_long_long = 0;
            if (format[i] == 'l') {
                is_long_long = 1;
                i++;
            }

            if (format[i] == 'd' || format[i] == 'i') {
                int64_t val = is_long_long ? va_arg(args, long long) : va_arg(args, long);
                char num_buf[32];
                size_t num_len = itoa(val, num_buf, 10);

                for (size_t j = 0; j < num_len; j++) {
                    buffer[buf_pos++] = num_buf[j];
                    if (buf_pos >= sizeof(buffer) - 1) {
                        uelf_write_log(buffer, buf_pos);
                        buf_pos = 0;
                    }
                }
            }
            else if (format[i] == 'u') {
                uint64_t val = is_long_long ? va_arg(args, unsigned long long) : va_arg(args, unsigned long);
                char num_buf[32];
                size_t num_len = utoa(val, num_buf, 10);

                for (size_t j = 0; j < num_len; j++) {
                    buffer[buf_pos++] = num_buf[j];
                    if (buf_pos >= sizeof(buffer) - 1) {
                        uelf_write_log(buffer, buf_pos);
                        buf_pos = 0;
                    }
                }
            }
            else if (format[i] == 'x' || format[i] == 'X') {
                uint64_t val = is_long_long ? va_arg(args, unsigned long long) : va_arg(args, unsigned long);
                char num_buf[32];
                size_t num_len = utoa(val, num_buf, 16);

                if (format[i] == 'X') {
                    for (size_t j = 0; j < num_len; j++) {
                        if (num_buf[j] >= 'a' && num_buf[j] <= 'f') {
                            num_buf[j] = num_buf[j] - 'a' + 'A';
                        }
                    }
                }

                for (size_t j = 0; j < num_len; j++) {
                    buffer[buf_pos++] = num_buf[j];
                    if (buf_pos >= sizeof(buffer) - 1) {
                        uelf_write_log(buffer, buf_pos);
                        buf_pos = 0;
                    }
                }
            }
        }
        else {
            // Unknown format, just print it
            buffer[buf_pos++] = '%';
            buffer[buf_pos++] = format[i];
        }

        if (buf_pos >= sizeof(buffer) - 1) {
            uelf_write_log(buffer, buf_pos);
            buf_pos = 0;
        }
    }

    // Flush remaining buffer
    if (buf_pos > 0) {
        uelf_write_log(buffer, buf_pos);
    }

    va_end(args);
}