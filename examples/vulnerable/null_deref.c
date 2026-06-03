#include <stdlib.h>
#include <string.h>

void null_deref(char *input) {
    char *p = malloc(64);
    strcpy(p, input);
}
