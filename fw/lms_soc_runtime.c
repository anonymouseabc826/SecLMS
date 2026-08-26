#include <stddef.h>
#include <stdint.h>

void *memcpy(void *destination, const void *source, size_t length)
{
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;
    /* 4B-aligned fast path (RV32 little-endian): security-domain/tree-cache/signature-assembly hot
     * paths do heavy memcpy; 4x vs byte-by-byte; unaligned falls back to byte-by-byte (equivalent). */
    if ((((uintptr_t)out | (uintptr_t)in) & 3u) == 0u && (length & 3u) == 0u) {
        uint32_t *out32 = (uint32_t *)(void *)out;
        const uint32_t *in32 = (const uint32_t *)(const void *)in;
        length >>= 2;
        while (length-- > 0u) {
            *out32++ = *in32++;
        }
        return destination;
    }
    while (length-- > 0u) {
        *out++ = *in++;
    }
    return destination;
}

void *memset(void *destination, int value, size_t length)
{
    unsigned char *out = (unsigned char *)destination;
    /* 4B-aligned fast path: write full 32-bit patterns (RV32 little-endian) */
    if ((((uintptr_t)out & 3u) == 0u) && (length & 3u) == 0u) {
        uint32_t pattern = (uint32_t)(unsigned char)value;
        pattern |= pattern << 8;
        pattern |= pattern << 16;
        uint32_t *out32 = (uint32_t *)(void *)out;
        length >>= 2;
        while (length-- > 0u) {
            *out32++ = pattern;
        }
        return destination;
    }
    while (length-- > 0u) {
        *out++ = (unsigned char)value;
    }
    return destination;
}

int memcmp(const void *left, const void *right, size_t length)
{
    const unsigned char *a = (const unsigned char *)left;
    const unsigned char *b = (const unsigned char *)right;
    /* 4B-aligned fast path: compare equality word by word; on mismatch, locate byte by byte */
    if ((((uintptr_t)a | (uintptr_t)b) & 3u) == 0u && (length & 3u) == 0u) {
        const uint32_t *a32 = (const uint32_t *)(const void *)a;
        const uint32_t *b32 = (const uint32_t *)(const void *)b;
        length >>= 2;
        while (length-- > 0u) {
            if (*a32 != *b32) {
                /* Locate the first differing byte (returns the difference, same semantics as the byte-by-byte version) */
                a = (const unsigned char *)a32;
                b = (const unsigned char *)b32;
                while (*a == *b) {
                    a++;
                    b++;
                }
                return (int)*a - (int)*b;
            }
            a32++;
            b32++;
        }
        return 0;
    }
    while (length-- > 0u) {
        if (*a != *b) {
            return (int)*a - (int)*b;
        }
        a++;
        b++;
    }
    return 0;
}

/* The firmware has no heap: malloc/free returning NULL is correct behavior - every code path
 * needing dynamic allocation falls back after detecting NULL (e.g. lms_hash_parts returns
 * LMS_ERR_INVALID). Bench-style firmware that provides its own bare-metal allocator defines
 * LMS_RUNTIME_NO_ALLOC to skip this definition, avoiding duplicate symbols. */
#ifndef LMS_RUNTIME_NO_ALLOC
#include <stdlib.h>
void *malloc(size_t size)
{
    (void)size;
    return NULL;
}

void free(void *ptr)
{
    (void)ptr;
}
#endif

/* ---- string/memory helpers (not referenced by the LMS firmware -> stripped by
 * --gc-sections, zero area impact) ---- */
void *memmove(void *destination, const void *source, size_t length)
{
    unsigned char *out = (unsigned char *)destination;
    const unsigned char *in = (const unsigned char *)source;

    if (out < in) {
        while (length-- > 0u) {
            *out++ = *in++;
        }
    } else if (out > in) {
        out += length;
        in += length;
        while (length-- > 0u) {
            *--out = *--in;
        }
    }
    return destination;
}

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p != '\0') {
        p++;
    }
    return (size_t)(p - s);
}

int strcmp(const char *a, const char *b)
{
    while (*a != '\0' && *a == *b) {
        a++;
        b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    while (n-- > 0u && *a != '\0' && *a == *b) {
        a++;
        b++;
    }
    if (n == (size_t)-1) {
        return 0;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

char *strchr(const char *s, int c)
{
    char ch = (char)c;
    while (*s != '\0') {
        if (*s == ch) {
            return (char *)s;
        }
        s++;
    }
    return (ch == '\0') ? (char *)s : NULL;
}

char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    char ch = (char)c;
    while (*s != '\0') {
        if (*s == ch) {
            last = s;
        }
        s++;
    }
    if (ch == '\0') {
        return (char *)s;
    }
    return (char *)last;
}

char *strstr(const char *haystack, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0u) {
        return (char *)haystack;
    }
    while (*haystack != '\0') {
        if (*haystack == *needle &&
            strncmp(haystack, needle, nlen) == 0) {
            return (char *)haystack;
        }
        haystack++;
    }
    return NULL;
}

void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *p = (const unsigned char *)s;
    unsigned char ch = (unsigned char)c;
    while (n-- > 0u) {
        if (*p == ch) {
            return (void *)p;
        }
        p++;
    }
    return NULL;
}

char *strcpy(char *destination, const char *source)
{
    char *out = destination;
    while ((*out++ = *source++) != '\0') {
    }
    return destination;
}

char *strncpy(char *destination, const char *source, size_t n)
{
    char *out = destination;
    while (n-- > 0u && (*out++ = *source++) != '\0') {
    }
    while (n-- > 0u) {
        *out++ = '\0';
    }
    return destination;
}