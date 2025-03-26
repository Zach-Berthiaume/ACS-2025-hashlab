#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "Hashes.h"

// doing 32 bit blocks
#define CHUNK_SIZE 4
#define INITIALIZATION_VECTOR 420

// usage: Takes one argument - the input file
// example: ./StudentHashRunner testfile.txt
int main(int argc, char **argv)
{

    char chunk[CHUNK_SIZE + 1];
    char *buf = NULL;
    size_t buf_len = 0;
    unsigned int read;
    FILE *file = fopen(argv[1], "r");
    if (!file)
        return 1;
    while ((read = fread(chunk, 1, CHUNK_SIZE, file)) > 0)
    {
        // padding with zeros
        for (int i = read; i < CHUNK_SIZE; i++)
        {
            chunk[i] = 0;
        }
        size_t old_len = buf_len;
        buf_len += CHUNK_SIZE; // length will always be multiple of chunk size due to padding

        // append chunk to buffer
        buf = (char *)realloc(buf, sizeof(char) * buf_len);
        for (int i = 0; i < CHUNK_SIZE; i++)
        {
            buf[old_len + i] = chunk[i];
        }
    }

    // now we call the function
    unsigned int dig;
    StudentHash(buf, buf_len, 0, &dig);

    // the 08 means we always want to print 8 bytes
    printf("%08x  %s\n", dig, argv[1]);
    /* printf("%08i %s\n", dig, argv[1]); */
    return 0;
}
