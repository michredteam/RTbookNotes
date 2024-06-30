#include <stdio.h>
#include <stdlib.h>

int main() {
  // Code to exploit the vulnerability and gain system privileges
  // Insert your malicious code here

  // Create a task to run cmd.exe with administrator permissions
  system("schtasks /create /tn MyTask /tr \"cmd.exe /k echo Congratulations! You now have administrative privileges.\" /sc onlogon /rl highest /f");

  printf("Task created successfully! When the user logs on, cmd.exe will run with administrator permissions.\n");

  return 0;
}

