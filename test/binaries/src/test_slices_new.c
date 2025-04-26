#include <stdio.h>
#include <string.h>


char* my_strcpy(char* d, char* s)  {
	int i;
	
	for (i = 0; s[i]; i++) {
		d[i] = s[i];
	}

	d[i] = 0;
}

int main() {
    char input[50] = {0};
	scanf("%49s", &input);
	char buf[50] = {0};

	my_strcpy(buf, input);

	printf(buf);

	return 0;
}

