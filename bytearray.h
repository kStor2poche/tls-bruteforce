#ifndef BYTEARRAY_H
#define BYTEARRAY_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct _bytearray{
   unsigned char *data;
   size_t len;
} bytearray;

// https://gist.github.com/xsleonard/7341172
bytearray hexstr_to_bytearray(const char* hexstr);

void print_barray(bytearray b);

#endif
