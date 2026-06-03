#include <stdlib.h>
#include <string.h>

void alloc_items(size_t count, char *src) {
    size_t size = count * sizeof(int);
    int *buf = malloc(size);
    memcpy(buf, src, count * sizeof(int));
}
