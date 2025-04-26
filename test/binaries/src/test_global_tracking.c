/*
    [NAME] test_global_tracking 
    [INFO] This test case will prove out a few things:
        1) `is_function_tainted` functionality
        2) global variable tracking
        3) return variable tainting 
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>


char glob_buf[0x100];

char *scramble_data(char *src) {
    int i;
    char *new_buf = (char *)malloc(strlen(src) * sizeof(char));

    if (new_buf == NULL) {
        printf("Memory allocation failed!\n");
        return NULL;
    }

    for (i = 0; i < strlen(src); i++) {
        new_buf[i] = (src[i] ^ 0xde) & 0x7E;
    }

    new_buf[strlen(src)] = '\0';
    return new_buf;
}
int main() {
    char user_buf[0x100];

    fgets(user_buf, 0x100, stdin);

    char * encrypted_text = scramble_data(user_buf);
    strcpy(glob_buf, encrypted_text);
    printf(glob_buf);
}