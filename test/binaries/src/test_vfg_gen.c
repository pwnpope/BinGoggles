#include <stdio.h>
#include <stdlib.h>

int calc(int a, int b) {
    int res = 0;
    if (a > 5) {
        res = a + b;
        if (b % 2 == 0) {
            res *= 2;
        } else {
            res -= 3;
        }
    } else {
        res = a - b;
        if (a == b) {
            res = 42;
        }
    }
    return res;
}

void jumpy(int x) {
    int y = 10;
    if (x > 0)
        goto positive;
    else if (x == 0)
        goto zero;
    else
        goto negative;

positive:
    y += x;
    goto end;

zero:
    y = 0;
    goto end;

negative:
    y -= x;

end:
    printf("jumpy: %d\n", y);
}

void layered(int input) {
    int a = input + 1;
    int b = calc(a, input);
    if (b > 50) {
        b = b / 2;
        if (input % 3 == 0) {
            a = a * b;
        }
    } else {
        a = b - input;
        jumpy(a - b);
    }

    printf("Result: %d\n", a + b);
}

int main() {
    for (int i = -2; i < 3; i++) {
        layered(i);
    }

    return 0;
}
