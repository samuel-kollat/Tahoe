#ifndef __MIDDLEND_PROTOCOLS_L2__
#define __MIDDLEND_PROTOCOLS_L2__

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>

#define L2_HEADER_LENGTH 14

typedef struct {
    uint8_t dsthw[6];
    uint8_t srchw[6];
    uint8_t proto[2];
} l2_header;

#endif