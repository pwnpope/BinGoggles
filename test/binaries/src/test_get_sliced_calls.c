#include <stdio.h>


int do_add(int a, int c) {
      return a + c;
}


int main() {
      int a = 0, tom_var = 0;
      printf("Welcome, submit two numbers for addition\n");
      
      printf("A: ");
      scanf("%d", &a);

      printf("B: ");
      scanf("%d", &tom_var);

      int return_var = do_add(a, tom_var);
      printf("%d", return_var);

      return 0;
}