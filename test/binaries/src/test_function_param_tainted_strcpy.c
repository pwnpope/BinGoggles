#include <string.h>
#include <stdio.h>


void test_shared_object_one(void *arg1, void *arg2, void *arg3) {
    /*
        strcpy test case
    */
   printf("Running the strcpy test (test_shared_object_one)");
   printf("dummy %s", arg2);

   strcpy(arg1, arg3);
}

int main() {
    char buf_one[100];
    char buf_two[100];
    char buf_three[50] = {0};
    memcpy(buf_three, "hello world", 11);

    printf("buf one: ");
    fgets(buf_one, 100, stdin);

    printf("buf two: ");
    fgets(buf_two, 100, stdin);

    test_shared_object_one(buf_one, buf_three, buf_two);
    return 0;

}