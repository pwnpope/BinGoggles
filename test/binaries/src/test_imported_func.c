#include <string.h>
#include <stdio.h>

int main() {
    char buf[0x200];
    char user_input[0x200];
    fgets(buf, 0x200, stdin);
    strcpy(user_input, buf);

    printf("%s", user_input);
    return 0;
}