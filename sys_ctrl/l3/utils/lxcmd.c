/*
 * sys_ctrl/l3/utils/lxcmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of the units that #include it.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/lxcmd.c
 *
 * The main() of the command-line tools (l2cmd): the system controller
 * options (SCapi.c), then the rest of the line as commands for the L2,
 * ";" between them. #included by the tool's .c file, which defines myname
 * and usage().
 */

#include <string.h>

int main(int argc, char **argv)
{
  IRAddress addr = IR_ADDR_MAKE(IR_ADDR_L2,0x3ff,0x3f,0,IR_L2_CMD);   /* the L2's command task */
  size_t len = 1;
  char *cmdline;
  char *clptr;
  char *cmd;
  char *rsp;
  int serial = 1;
  int status;
  int i;

  myname = argv[0];
  if (sn1SCParseCmdline(&argc,argv,&serial) < 0) {
    fprintf(stderr,"%s: error while parsing library command arguments\n",myname);
    exit(-1);
  }
  if (argc < 2)
    usage();
  /* the words, each followed by a space. (The original joined them in
   * 1024 bytes.) */
  for (i = 1; i < argc; i++)
    len += strlen(argv[i]) + 1;
  cmdline = malloc(len);
  cmdline[0] = '\0';
  for (i = 1; i < argc; i++) {
    strcat(cmdline,argv[i]);
    strcat(cmdline," ");
  }
  if (sn1SCInit(myname,NULL,0) < 0)
    exit(-1);
  clptr = cmdline;
  do {
    cmd = clptr;
    clptr = strchr(clptr,';');
    if (clptr != NULL)
      *clptr++ = '\0';
    status = sn1SCTextCmd(&addr,cmd,&rsp);
    if (rsp != NULL)
      fputs(rsp,status == 0 ? stdout : stderr);
  } while (clptr != NULL && *clptr != '\0');
  return status;
}
