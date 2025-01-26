#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

/**--
   bytearray   
          --**/
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

void print_bytearray_sub(char *name, bytearray b) {
    printf("%s: .len = %lu, .data = ", name, b.len);
    for (size_t i = 0; i<b.len; i++) {
        printf("%02x", b.data[i]);
    }
    puts("");
}

/**--
   port list   
          --**/
port_list parse_port_list(char* ports_str)
{
    int nr = 0;
    for (int i = 0; ports_str[i] != 0; i++) {
        nr += (ports_str[i] == ',');
    }

    int len = nr + 1;
    port_list ret = (port_list) { .ports = malloc(sizeof(uint16_t) * nr), .len = len };

    char* next = ports_str;
    for (int i = 0; i < len; i++) {
        ret.ports[i] = strtoul(next, &next, 10);
        next++;
    }

    return ret;
}

void print_port_list(port_list self) {
    putc('[', stdout);
    for (int i = 0; i < self.len; i++) {
        printf("%u, ", self.ports[i]);
    }
    puts("]");
}

void free_list(port_list self)
{
    free(self.ports);
}

