#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>


char *combine(char *buf_one, char* buf_two) {
    return strcat(buf_one, buf_two);
}

int main() {
    char user_input_one[0x50] = {0};
    char user_input_two[0x50] = {0};

    printf("Input One: ");
    fflush(stdout);
    read(0, user_input_one, 0x50);

    printf("Input Two: ");
    fflush(stdout);
    read(0, user_input_two, 0x50);


    printf("Thanks, your combined input is: %s", combine(user_input_one, user_input_two));
    printf("Individually:\nInput One: %s\nInput Two: %s", user_input_one, user_input_two);
    return 0;
}
