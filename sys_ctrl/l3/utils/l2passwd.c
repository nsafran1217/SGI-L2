/*
 * sys_ctrl/l3/utils/l2passwd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/l2passwd.c
 */

#include "../l2/l2.h"   /* needed by the reconstruction */
#include "l2passwd.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include "../main/nvram.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int main(int argc, char **argv)
{
  char *nv_pw;
  char *cpw;
  FILE *pwin;
  FILE *pwout;
  struct passwd *pwent;
  char *__command;
  int iVar1;
  
  nvramInit(1);
  nv_pw = (char *)nvramGet(0x13);
  if ((nv_pw == NULL) || (*nv_pw == '\0')) {
    cpw = NULL;
  }
  else {
    cpw = crypt(nv_pw,"L2");
  }
  system("rm -f /etc/passwd.bak; /bin/cp /etc/passwd /etc/passwd.bak");
  pwin = (FILE *)fopen("/etc/passwd.bak","r");
  pwout = (FILE *)fopen("/etc/passwd","w+");
  while( true ) {
    pwent = (struct passwd *)fgetpwent((FILE *)pwin);
    if (pwent == NULL) break;
    iVar1 = strcmp(pwent->pw_name,"root");
    if (iVar1 == 0) {
      pwent->pw_passwd = cpw;
    }
    putpwent((struct passwd *)pwent,(FILE *)pwout);
  }
  fclose((FILE *)pwin);
  fclose((FILE *)pwout);
  system("/bin/rm /etc/passwd.bak");
  if (cpw == NULL) {
    __command = "/bin/cp /rhosts.allow /etc/.rhosts";
  }
  else {
    __command = "/bin/rm -f /etc/.rhosts";
  }
  iVar1 = system(__command);
  return iVar1;
}
