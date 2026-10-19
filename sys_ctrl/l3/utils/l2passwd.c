/*
 * sys_ctrl/l3/utils/l2passwd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/l2passwd.c
 *
 * l2passwd: the L3 host's root password follows the L2's (run as root at
 * boot).
 */

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "l2passwd.h"
#include "../main/nvram.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */

/* Set the L3's root password from the L2 NVRAM password (none: no password,
 * and rhosts access is enabled). Every file it touches is under SGI_L3_ROOT
 * (default "", the real system files, as in the original). */
int main(int argc, char **argv)
{
  char *nv_pw;
  char *cpw;
  FILE *pwin;
  FILE *pwout;
  struct passwd *pwent;
  const char *root = l3path_root();
  char passwd[1024], backup[1024], rhosts[1024], allow[1024], cmd[4200];

  snprintf(passwd, sizeof(passwd), "%s/etc/passwd", root);
  snprintf(backup, sizeof(backup), "%s/etc/passwd.bak", root);
  snprintf(rhosts, sizeof(rhosts), "%s/etc/.rhosts", root);
  snprintf(allow, sizeof(allow), "%s/rhosts.allow", root);

  nvramInit(NVRAM_READONLY);
  nv_pw = (char *)nvramGet(NVRAM_PASSWORD);
  if ((nv_pw == NULL) || (*nv_pw == '\0')) {
    cpw = NULL;
  }
  else {
    cpw = crypt(nv_pw,"L2");
  }
  /* original: "rm -f /etc/passwd.bak; /bin/cp /etc/passwd /etc/passwd.bak" */
  snprintf(cmd, sizeof(cmd), "rm -f '%s'; /bin/cp '%s' '%s'", backup, passwd, backup);
  system(cmd);
  /* (the original opened, and so emptied, the password file even when it
   * had no copy to read it back from) */
  pwin = fopen(backup,"r");
  if (pwin == NULL) {
    fprintf(stderr,"l2passwd: can\'t read %s, %s; %s left as it was\n",backup,strerror(errno),passwd);
    return 1;
  }
  pwout = fopen(passwd,"w+");
  if (pwout == NULL) {
    fprintf(stderr,"l2passwd: can\'t write %s, %s\n",passwd,strerror(errno));
    fclose(pwin);
    return 1;
  }
  while ((pwent = fgetpwent(pwin)) != NULL) {
    if (strcmp(pwent->pw_name,"root") == 0) {
      pwent->pw_passwd = cpw;
    }
    putpwent(pwent,pwout);
  }
  fclose(pwin);
  fclose(pwout);
  snprintf(cmd, sizeof(cmd), "/bin/rm '%s'", backup);
  system(cmd);
  if (cpw == NULL) {
    snprintf(cmd, sizeof(cmd), "/bin/cp '%s' '%s'", allow, rhosts);
  }
  else {
    snprintf(cmd, sizeof(cmd), "/bin/rm -f '%s'", rhosts);
  }
  return system(cmd);
}
