// test_interproc_analysis.c
#include <stdio.h>

char* my_strcpy(char* d, char* s) {
    int i;
    for (i = 0; s[i]; i++) {
        d[i] = s[i];
    }
    d[i] = 0;
    return d;
}

// === LAYER 3 ===
int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

// === LAYER 2 ===
int compute_sum_diff(int a, int b) {
    int x = add(a, b);
    int y = sub(a, b);
    return x * y;
}

void copy_and_modify(char* dst, char* src, int shift) {
    my_strcpy(dst, src);

    // modify each char a little
    for (int i = 0; dst[i]; i++) {
        dst[i] = dst[i] + shift;
    }
}

// === LAYER 1 ===
int process(char* dst, char* src, int a, int b) {
    copy_and_modify(dst, src, 1);
    return compute_sum_diff(a, b);
}

int main() {
    char src[32] = "hello";
    char dst[32];
    int result = process(dst, src, 5, 3);
    printf("%d", result);

    return 0;
}
