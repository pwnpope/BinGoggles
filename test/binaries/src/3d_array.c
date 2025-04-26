#include <stdio.h>

int main() {
    int array[2][3][4] = {
        {
            {1, 2, 3, 4},
            {5, 6, 7, 8},
            {9, 10, 11, 12}
        },
        {
            {13, 14, 15, 16},
            {17, 18, 19, 20},
            {21, 22, 23, 24}
        }
    };

    for (int layer = 0; layer < 2; ++layer) {
        for (int row = 0; row < 3; ++row) {
            for (int col = 0; col < 4; ++col) {
                printf("array[%d][%d][%d] = %d\n", layer, row, col, array[layer][row][col]);
            }
        }
    }

    return 0;
}
