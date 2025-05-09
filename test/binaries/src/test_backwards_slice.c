#include <stdio.h>

void foo(char* a, char* b) {
    char x[256];

    // Use a and b explicitly to prevent optimization
    printf("Received a: %s, b: %s\n", a, b);  // Printing the values of a and b

    puts("Reading input into x...");
    fgets(x, sizeof(x), stdin);  // Read user input into x

    puts("Doing something else...");
    char z[256];
    snprintf(z, sizeof(z), "Processed: %s", x);  // Process input and store it in z

    // Now use b to store the address of x
    b = x; 

    // Print something related to b
    printf("Now b points to: %s\n", b);  // Will print contents of x, since b = x
}

int main() {
    // Initialize input and b with meaningful values
    char input[] = "Initial input";  // String for input
    char b[256] = "Initial b value"; // Initial value for b

    // Call foo, passing meaningful values for a and b
    foo(input, b);
    
    return 0;
}
