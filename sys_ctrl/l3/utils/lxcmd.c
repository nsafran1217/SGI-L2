/*
 * sys_ctrl/l3/utils/lxcmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of the units that #include it.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/lxcmd.c
 */

/* #included by another .c file, not compiled on its own */

int main(int argc, char **argv)
{
  char *cmd;
  int status;
  int iVar1;
  FILE *__stream;
  char *curcmd;
  char *rsp;
  char *clptr;
  char cmdline [1024];
  IRAddress addr;
  int serial;
  
  serial = 1;
  myname = *argv;
  status = sn1SCParseCmdline(&argc,argv,&serial);
  if (status < 0) {
    fprintf(stderr,"%s: error while parsing library command arguments\n",myname);
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  if (argc < 2) {
    usage();
  }
  cmdline[0] = '\0';
  while (argc = argc + -1, argc != 0) {
    argv = argv + 1;
    strcat(cmdline,*argv);
    strcat(cmdline," ");
  }
  iVar1 = sn1SCInit(myname,NULL,0);
  if (-1 < iVar1) {
    addr = 0x1ffff003;
    clptr = cmdline;
    do {
      cmd = clptr;
      clptr = strchr(clptr,0x3b);
      if (clptr != NULL) {
        *clptr = '\0';
        clptr = clptr + 1;
      }
      iVar1 = sn1SCTextCmd(&addr,cmd,&rsp);
      if (rsp != NULL) {
        __stream = stderr;
        if (iVar1 == 0) {
          __stream = stdout;
        }
        fputs(rsp,__stream);
      }
    } while ((clptr != NULL) && (*clptr != '\0'));
    return iVar1;
  }
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
