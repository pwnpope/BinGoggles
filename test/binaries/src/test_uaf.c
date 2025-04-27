#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void level_one() {
    char *user_input;

    user_input = (char *)malloc(100 * sizeof(char));
    if (user_input == NULL) {
        perror("malloc failed");
        return;
    }

    printf("Enter a string: ");
    fgets(user_input, 100, stdin);

    free(user_input);
    printf("Memory has been freed.\n");

    fgets(user_input, 100, stdin); // UAF occurs here
    printf("Content after writing: %s\n", user_input); // UAF
}

void level_two() {
    char *buffer = (char *)malloc(100 * sizeof(char));

    if (buffer == NULL) {
        perror("malloc failed");
        return;
    }

    printf("Enter a string for level_two: ");
    fgets(buffer, 100, stdin);

    // Using realloc to "free" the buffer. This is the key UAF demonstration.
    // realloc with size 0 is equivalent to freeing the memory.
    buffer = (char *)realloc(buffer, 0);  // realloc to free the buffer (buffer is now invalid)

    // After realloc, the buffer is invalid, but we still use it.
    printf("Buffer after realloc (freed memory): ");
    fgets(buffer, 100, stdin); // UAF occurs here, buffer is freed but used
    printf("Content after writing: %s\n", buffer); // UAF
}

void level_three() {
    char *buffer = (char *)malloc(100 * sizeof(char));
    char *tmp_buffer;

    if (buffer == NULL) {
        perror("malloc failed");
        return;
    }

    printf("Enter a string for level_three (before free): ");
    fgets(buffer, 100, stdin);
    printf("Buffer before freeing: %s\n", buffer);

    free(buffer);

    tmp_buffer = (char *)malloc(100 * sizeof(char)); // Reallocates memory
    if (tmp_buffer == NULL) {
        perror("malloc failed");
        return;
    }

    printf("Enter a string for level_three (after free, but before buffer moves): ");
    fgets(tmp_buffer, 100, stdin);

    // After memory has been freed and reallocated, test if old data persists
    printf("Buffer after reallocating and writing new content: %s\n", tmp_buffer);

    // Use the old buffer that was freed
    printf("Content from old freed buffer: %s\n", buffer);
    free(tmp_buffer);
}

void level_four() {
    char *buffer_a = (char *)malloc(100 * sizeof(char));
    char *buffer_b;

    if (buffer_a == NULL) {
        perror("malloc failed");
        return;
    }

    printf("Enter a string for level_four (buffer_a): ");
    fgets(buffer_a, 100, stdin);
    printf("Buffer A before freeing: %s\n", buffer_a);

    free(buffer_a); // Free buffer_a in this function

    buffer_b = buffer_a; // reassign buffer_a after the free

    // We have passed the freed buffer to buffer_b, and now we use it
    printf("Buffer B after passing freed buffer: ");
    fgets(buffer_b, 100, stdin); // UAF occurs here

    printf("Content from buffer_b after UAF: %s\n", buffer_b); // UAF
}

void free_buffer(char *buffer) {
    // This function will receive the buffer, free it, and simulate use-after-free.
    printf("Buffer passed to free_buffer, will be freed here.\n");
    free(buffer);
}

void level_five() {
    char *buffer_1 = (char *)malloc(100 * sizeof(char));

    if (buffer_1 == NULL) {
        perror("malloc failed");
        return;
    }

    // Fill buffer_1 with data
    printf("Enter a string for level_five (buffer_1): ");
    fgets(buffer_1, 100, stdin);
    printf("Buffer_1 before passing to free_buffer: %s\n", buffer_1);

    // Pass the buffer to another function and free it there
    free_buffer(buffer_1);

    // Now use the freed buffer (which has been passed and freed in `free_buffer`)
    printf("Buffer_1 after being freed in free_buffer (UAF): ");
    fgets(buffer_1, 100, stdin); // UAF occurs here, buffer_1 is freed in free_buffer but used in level_five
    printf("Content from buffer_1 after UAF: %s\n", buffer_1); // UAF
}

void level_six() {
    char *buffer = (char *)malloc(100 * sizeof(char));
    int new_size;

    if (buffer == NULL) {
        perror("malloc failed");
        return;
    }

    printf("Enter a string for level_six (buffer): ");
    fgets(buffer, 100, stdin);

    // Ask the user for the new size to realloc
    printf("Enter the new size for realloc: ");
    scanf("%d", &new_size);

    // Reallocate memory with user-controlled size
    buffer = (char *)realloc(buffer, new_size);  // User controls the size here

    // After realloc, we attempt to use the buffer again, potentially causing a vulnerability
    if (new_size > 0) {
        printf("Buffer after realloc: ");
        fgets(buffer, new_size, stdin); // Using the reallocated buffer
        printf("Content after realloc: %s\n", buffer);
    } else {
        // If realloc size is 0, the buffer is freed
        printf("Buffer has been freed after realloc with size 0.\n");
    }

    // We still use the buffer (it could be freed if realloc size is 0)
    printf("Buffer content after reallocation: %s\n", buffer);
    free(buffer);
}

#include <stdio.h>
#include <stdlib.h>

void level_seven() {
    char *buffer;

    // Step 1: Allocate memory
    buffer = (char *)malloc(100 * sizeof(char));
    if (buffer == NULL) {
        perror("Initial malloc failed");
        return;
    }

    // Step 2: Use the buffer
    printf("Enter a string for level_seven (initial buffer): ");
    if (fgets(buffer, 100, stdin) == NULL) {
        perror("Error reading input");
        free(buffer);
        return;
    }
    printf("Buffer content before freeing: %s\n", buffer);

    // Step 3: Free the buffer
    free(buffer);
    buffer = NULL;

    // Step 4: Reallocate the buffer
    buffer = (char *)malloc(100 * sizeof(char));
    if (buffer == NULL) {
        perror("Re-malloc failed");
        return;
    }

    // Step 5: Use the reallocated buffer
    printf("Enter a new string for level_seven (reallocated buffer): ");
    if (fgets(buffer, 100, stdin) == NULL) {
        perror("Error reading input");
        free(buffer);
        return;
    }
    printf("Buffer content after reallocation: %s\n", buffer);

    // Step 6: Clean up
    free(buffer);
}

// ========================
// === Level 8 Deep UAF ===
// ========================

void do_free(char *buffer) {
    printf("[do_free] Freeing buffer...\n");
    free(buffer);
}

void deeper_function(char *buffer) {
    printf("[deeper_function] Passing buffer to do_free\n");
    do_free(buffer); // buffer is freed here, 2nd layer
}

void deeper_and_deeper(char *buffer) {
    printf("[deeper_and_deeper] Passing buffer to deeper_function\n");
    deeper_function(buffer); // 3rd layer
}

void level_eight() {
    char *buffer = (char *)malloc(100 * sizeof(char));
    if (buffer == NULL) {
        perror("malloc failed");
        return;
    }

    printf("Enter a string for level_eight (buffer): ");
    fgets(buffer, 100, stdin);
    printf("Buffer content before deep free: %s\n", buffer);

    // Call chain: level_eight() -> deeper_and_deeper() -> deeper_function() -> do_free()
    deeper_and_deeper(buffer); // buffer gets freed somewhere deep

    printf("[level_eight] Trying to reuse freed buffer (UAF):\n");

    // This is the actual UAF site
    fgets(buffer, 100, stdin); // Use-after-free
    printf("Content from UAF buffer: %s\n", buffer);
}

int main() {
    // Test all the levels
    printf("Running level_one:\n");
    level_one();
    printf("\nRunning level_two:\n");
    level_two();
    printf("\nRunning level_three:\n");
    level_three();
    printf("\nRunning level_four:\n");
    level_four();
    printf("\nRunning level_five:\n");
    level_five();
    printf("\nRunning level_six:\n");
    level_six();
    printf("\nRunning level_seven:\n");
    level_seven();
    printf("\nRunning level_eight:\n");
    level_eight();

    return 0;
}
