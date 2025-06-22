#include <string.h>
#include <stdio.h>

void test_shared_object_four(void *arg1, void *arg2, void *arg3) {
    printf("dummy %s\n", arg2);
    memcpy(arg1, arg3, 100);
}

int main() {
    char buf_one[100];
    char buf_two[100];
    char buf_three[100];

    printf("user input: ");
    fgets(buf_two, sizeof(buf_two), stdin);

    memcpy(buf_three, buf_two, 100);

    test_shared_object_four(buf_one, buf_three, buf_two);
    printf(buf_one);

    return 0;
}
