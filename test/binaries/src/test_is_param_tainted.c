#include <stdio.h>
#include <string.h>
#include <unistd.h>


char glob_buf[0x20];

float do_division(float a, float b, char *name) {
    printf("cock: %s", name);
    printf("okay, dividing the two numbers\n");
    float result = b / a;
    a = b;
    printf("%f / %f = %f",b, a, result);
    return result;
}

int do_math(int a, int b, char *result_name) {
    int result = (a + b);
    float result_divided = do_division((float)a, (float)b, "cockaldoddledoo");

    printf("adding %d + %d = %d and writing it to %s\n", a, b, result, result_name);
    printf("result divided: %f\n", result_divided);
    return result;
}
char* my_strcpy(char* d, char* s)  {
	int i;
	
	for (i = 0; s[i]; i++) {
		d[i] = s[i];
	}

	d[i] = 0;
}

void do_calculation_and_write_to_buf(int a, int b, int c, int d, void *result_name) {
    printf("var d: %d is unused\n", d);
    int just_for_fun = (b+d);
    int sum = (do_math(a, b, (char *)result_name) + do_math(a, c, (char *)result_name));
    my_strcpy(glob_buf, result_name);
    printf(glob_buf);
}

int get_integer(char *prompt) {
    int integer = 0;
    printf("%s", prompt);
    fflush(stdout);
    scanf("%d", &integer);
    return integer;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    int a = get_integer("Enter a: ");
    int b = get_integer("Enter b: ");
    int c = get_integer("Enter c: ");
    int d = 100;
    char buf[0x20];

    printf("enter a name for the result: ");
    read(0, buf, 0x20);

    do_calculation_and_write_to_buf(a,b,c,d, buf);

    return 0;
}
