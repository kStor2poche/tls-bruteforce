#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct _bytearray{
   unsigned char *data;
   int len;
} bytearray;

// https://gist.github.com/xsleonard/7341172
bytearray hexstr_to_bytearray(const char* hexstr);
