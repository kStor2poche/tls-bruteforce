#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "bytearray.h"

// https://gist.github.com/xsleonard/7341172
bytearray hexstr_to_bytearray(const char* hexstr)
{
    size_t len = strlen(hexstr);
    size_t final_len = len / 2;
    bytearray bytes = {malloc(final_len), final_len};
    for (size_t i=0, j=0; j<final_len; i+=2, j++)
        bytes.data[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    return bytes;
}

bytearray new_bytearray(unsigned char *data, size_t len) {
    return (bytearray){.data= data, .len= len};
}
