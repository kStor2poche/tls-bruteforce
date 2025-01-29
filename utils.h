#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/**--
   bytearray   
          --**/
typedef struct _bytearray{
    unsigned char *data;
    size_t len;
} bytearray;

// https://gist.github.com/xsleonard/7341172
bytearray hexstr_to_bytearray(const char* hexstr);

void _debug_bytearray(char *name, bytearray b);

/**--
   port list   
          --**/
typedef struct _port_list {
    uint16_t *ports;
    size_t len;
} port_list;

port_list parse_port_list(char* ports_str);

void print_port_list(port_list self);

void free_port_list(port_list self);

#endif
