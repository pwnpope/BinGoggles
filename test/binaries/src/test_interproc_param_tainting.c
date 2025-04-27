// test_interproc_analysis_alt.c
#include <stdio.h>

// === LAYER 4 ===
void init_array(int* arr, int size, int start_val) {
    for (int i = 0; i < size; i++) {
        arr[i] = start_val + i;
    }
}

int multiply_and_add(int x, int y, int z) {
    return (x * y) + z;
}

// === LAYER 3 ===
void adjust_array(int* arr, int size, int offset) {
    for (int i = 0; i < size; i++) {
        arr[i] += offset;
    }
}

int compute_complex(int a, int b, int c, int d) {
    int part1 = multiply_and_add(a, b, c);
    int part2 = multiply_and_add(b, c, d);
    return part1 - part2;
}

// === LAYER 2 ===
void copy_and_shift(int* dst, int* src, int size, int shift) {
    for (int i = 0; i < size; i++) {
        dst[i] = src[i] + shift;
    }
}

int array_math(int* dst, int* src, int size, int a, int b) {
    copy_and_shift(dst, src, size, a);
    adjust_array(dst, size, b);
    return compute_complex(a, b, dst[0], src[0]);
}

// === LAYER 1 ===
int process_data(int* final_array, int* temp_array, int size, int start_val, int shift, int adjust_val) {
    init_array(temp_array, size, start_val);
    return array_math(final_array, temp_array, size, shift, adjust_val);
}

int main() {
    int temp[10];
    int final[10];

    int result = process_data(final, temp, 10, 5, 2, 3);
    printf("%d\n", result);

    return 0;
}
