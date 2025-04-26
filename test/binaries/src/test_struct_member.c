#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int *ptr;
    double *dblPtr;
    char *str;
    int valueCopy;  // New member to hold the value pointed to by ptr
} MyStruct;

void initializeStruct(MyStruct *myStruct) {
    // Allocate memory for the integer pointer
    myStruct->ptr = (int*)malloc(sizeof(int));
    if (myStruct->ptr == NULL) {
        printf("Memory allocation failed for integer pointer.\n");
        exit(1);
    }
    *myStruct->ptr = 42;

    // Assign the value pointed to by ptr to valueCopy
    myStruct->valueCopy = *myStruct->ptr;

    // Allocate memory for the double pointer
    myStruct->dblPtr = (double*)malloc(sizeof(double));
    if (myStruct->dblPtr == NULL) {
        printf("Memory allocation failed for double pointer.\n");
        free(myStruct->ptr);
        exit(1);
    }
    *myStruct->dblPtr = 3.14159;

    // Allocate memory for the string
    myStruct->str = (char*)malloc(50 * sizeof(char)); // Allocate space for 50 characters
    if (myStruct->str == NULL) {
        printf("Memory allocation failed for string.\n");
        free(myStruct->ptr);
        free(myStruct->dblPtr);
        exit(1);
    }
    snprintf(myStruct->str, 50, "Hello, World!");
}

void freeStruct(MyStruct *myStruct) {
    free(myStruct->ptr);
    free(myStruct->dblPtr);
    free(myStruct->str);
}

int main() {
    // Create a struct instance
    MyStruct myStruct;

    // Initialize the struct with memory allocations
    initializeStruct(&myStruct);

    // Print values before freeing memory
    printf("Before free:\n");
    printf("Integer: %d\n", *myStruct.ptr);
    printf("Value Copy: %d\n", myStruct.valueCopy);  // Print the copied value
    printf("Double: %.5f\n", *myStruct.dblPtr);
    printf("String: %s\n", myStruct.str);

    // Free the memory allocated for the integer, double, and string
    freeStruct(&myStruct);

    return 0;
}
