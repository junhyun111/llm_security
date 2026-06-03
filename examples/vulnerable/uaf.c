#include <stdlib.h>
#include <stdio.h>

void use_after_free() {
    char *p = malloc(32);
    free(p);
    printf("%s\n", p);
}
