#include <stdio.h>
#include <stdlib.h>

void * get_buf() {
    void *buf = malloc(0x200);
    return buf;
}

void normal_print(void *str) {
    printf("%s", str);
}
int main() {
    void *buf = get_buf();
    fgets(buf, 0x200, stdin);
    normal_print(buf);

    printf(buf);
    return 0;
}