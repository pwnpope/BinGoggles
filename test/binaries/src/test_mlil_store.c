#include <stdio.h>
#include <string.h>

int main() {
    int key_index = 5;
    char buf[11] = {0};
    buf[0] = 'H';
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'L';
    buf[4] = 'O';
    buf[5] = ' ';
    buf[6] = 'P';
    buf[7] = 'O';
    buf[8] = 'P';
    buf[9] = 'E';

    char encrypted_buf[10];

    for (int i = 0; i < strlen(buf) - 1; i++) {
        encrypted_buf[i] = 0x50 ^ buf[i];
    }

    printf("Original Buffer: %s\nEncrypted Buffer: %s\n", buf, encrypted_buf);

    return 0;
}