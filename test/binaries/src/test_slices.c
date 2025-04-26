#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

char * whoami = "user user user user";

char * test_var_1(int a) {
    void *f = malloc(0x50);
    char *res = strcpy(f, whoami);

    // Additional variables and operations
    int b = a + 1;
    char *g = (char *)malloc(0x30);
    strcpy(g, res);

    int c = b * 2;
    char *h = (char *)malloc(0x20);
    strncpy(h, g, 0x10);

    int d = c - 3;
    char *i = (char *)malloc(0x10);
    snprintf(i, 0x10, "%s_%d", h, d);

    free(f);
    free(g);
    free(h);

    return i;
}

int main(int argc, char * argv[]) {
    int a = 0;
    scanf("%d", &a);

    char *ptr = test_var_1(a);
    printf("%d", a);
    assert(ptr != 0);


    free(ptr);

    return 0;
}