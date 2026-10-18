/*
 * sys_ctrl/common/sys/brick_types.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/brick_types.c
 */

#include "PPP.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include "brick_types.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

unsigned int brickConvertString(char *sptr)
{
  size_t sVar1;
  int iVar2;
  unsigned int type;
  
  type = 0x3f;
  sVar1 = strlen(sptr);
  if (sVar1 == 1) {
    iVar2 = toupper((int)*sptr);
    if (true) {
      switch(iVar2) {
      case 0x23:
      case 0x25:
      case 0x26:
      case 0x3d:
      case 0x41:
      case 0x47:
      case 0x49:
      case 0x4a:
      case 0x4b:
      case 0x4e:
      case 0x50:
      case 0x52:
      case 0x58:
      case 0x59:
        type = toupper((int)*sptr);
      }
    }
  }
  else {
    iVar2 = strcmp(sptr,"ip35");
    if (iVar2 == 0) {
      type = 0x43;
    }
    else {
      iVar2 = strcmp(sptr,"ip37");
      if (iVar2 == 0) {
        type = 0x33;
      }
      else {
        iVar2 = strcmp(sptr,"ip45");
        if (iVar2 == 0) {
          type = 0x34;
        }
        else {
          iVar2 = strcmp(sptr,"ip41");
          if (iVar2 == 0) {
            type = 0x35;
          }
          else {
            iVar2 = strcmp(sptr,"twister");
            if (iVar2 == 0) {
              type = 0x36;
            }
            else {
              iVar2 = strcmp(sptr,"vortix");
              if (iVar2 == 0) {
                type = 0x40;
              }
              else {
                iVar2 = strcmp(sptr,"opus");
                if (iVar2 == 0) {
                  type = 0x4f;
                }
                else {
                  iVar2 = strcmp(sptr,"gemini");
                  if (iVar2 == 0) {
                    type = 0x42;
                  }
                  else {
                    iVar2 = strcmp(sptr,"dorado");
                    if (iVar2 == 0) {
                      type = 0x4c;
                    }
                    else {
                      iVar2 = strcmp(sptr,"ip69");
                      if (iVar2 == 0) {
                        type = 0x24;
                      }
                      else {
                        iVar2 = strcmp(sptr,"191010");
                        if (iVar2 == 0) {
                          type = 0x2e;
                        }
                        else {
                          iVar2 = strcmp(sptr,"1932");
                          if (iVar2 == 0) {
                            type = 0x2c;
                          }
                          else {
                            iVar2 = strcmp(sptr,"1955");
                            if (iVar2 == 0) {
                              type = 0x7d;
                            }
                            else {
                              iVar2 = strcmp(sptr,"drouter");
                              if (iVar2 == 0) {
                                type = 0x2d;
                              }
                              else {
                                iVar2 = strcmp(sptr,"ip71");
                                if (iVar2 == 0) {
                                  type = 0x7b;
                                }
                                else {
                                  iVar2 = strcmp(sptr,"nl4r");
                                  if (iVar2 == 0) {
                                    type = 0x44;
                                  }
                                  else {
                                    iVar2 = strcmp(sptr,"nl4s");
                                    if (iVar2 == 0) {
                                      type = 0x53;
                                    }
                                    else {
                                      iVar2 = strcmp(sptr,"T1");
                                      if (iVar2 == 0) {
                                        type = 0x31;
                                      }
                                      else {
                                        iVar2 = strcmp(sptr,"T2");
                                        if (iVar2 == 0) {
                                          type = 0x32;
                                        }
                                        else {
                                          iVar2 = strcmp(sptr,"T");
                                          if (iVar2 == 0) {
                                            type = 0x54;
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return type;
}

char *brickConvertType(unsigned int type)
{
  static char buff[16];
  
  if (false) {
switchD_08082331_caseD_27:
    sprintf((char *)&buff,"%c",type);
  }
  else {
    switch(type) {
    case 0x23:
      strcpy((char *)&buff,"PX");
      break;
    case 0x24:
      strcpy((char *)&buff,"C (IP69 HACK, 1932 Chassis)");
      break;
    case 0x25:
      strcpy((char *)&buff,"PE");
      break;
    case 0x26:
      strcpy((char *)&buff,"P0 N");
      break;
    default:
      goto switchD_08082331_caseD_27;
    case 0x2b:
      strcpy((char *)&buff,"Athena");
      break;
    case 0x2c:
      strcpy((char *)&buff,"1932 Chassis");
      break;
    case 0x2d:
      strcpy((char *)&buff,"Quad Dense Router");
      break;
    case 0x2e:
      strcpy((char *)&buff,"191010 Chassis");
      break;
    case 0x30:
      strcpy((char *)&buff,"CGN Voyager");
      break;
    case 0x33:
      strcpy((char *)&buff,"C (IP37)");
      break;
    case 0x34:
      strcpy((char *)&buff,"C (IP45)");
      break;
    case 0x35:
      strcpy((char *)&buff,"C (IP41)");
      break;
    case 0x36:
      strcpy((char *)&buff,"C (Twister)");
      break;
    case 0x37:
      strcpy((char *)&buff,"Chimera Server");
      break;
    case 0x38:
      strcpy((char *)&buff,"Chimera Blade");
      break;
    case 0x39:
      strcpy((char *)&buff,"Chimera WS");
      break;
    case 0x3d:
      strcpy((char *)&buff,"IX");
      break;
    case 0x3f:
      strcpy((char *)&buff,"Unknown");
      break;
    case 0x40:
      strcpy((char *)&buff,"C (Vortix)");
      break;
    case 0x42:
      strcpy((char *)&buff,"Gemini");
      break;
    case 0x43:
      strcpy((char *)&buff,"C (IP35)");
      break;
    case 0x44:
      strcpy((char *)&buff,"NL4R");
      break;
    case 0x45:
      strcpy((char *)&buff,"2UPX");
      break;
    case 0x46:
      strcpy((char *)&buff,"Opus TIO");
      break;
    case 0x4a:
      strcpy((char *)&buff,"PA");
      break;
    case 0x4b:
      strcpy((char *)&buff,"IA");
      break;
    case 0x4c:
      strcpy((char *)&buff,"Dorado");
      break;
    case 0x4d:
      strcpy((char *)&buff,"C (IP67)");
      break;
    case 0x4f:
      strcpy((char *)&buff,"Opus");
      break;
    case 0x51:
      strcpy((char *)&buff,"Rackmount WS");
      break;
    case 0x53:
      strcpy((char *)&buff,"NL4 Snooper");
      break;
    case 0x56:
      strcpy((char *)&buff,"CG Voyager");
      break;
    case 0x59:
      strcpy((char *)&buff,"X2");
      break;
    case 0x5e:
      strcpy((char *)&buff,"TIO Test Card");
      break;
    case 0x7b:
      strcpy((char *)&buff,"IP71");
      break;
    case 0x7d:
      strcpy((char *)&buff,"1955 Chassis");
    }
  }
  return buff;
}

char brickTypeToChar(unsigned int type)
{
  int iVar1;
  
  if (true) {
    switch(type) {
    case 0x23:
    case 0x25:
    case 0x4a:
      type = 0x70;
      break;
    case 0x24:
    case 0x2c:
    case 0x2e:
    case 0x30:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x46:
    case 0x4c:
    case 0x4d:
    case 0x4f:
    case 0x51:
    case 0x7b:
    case 0x7d:
      if (type == 0x41) {
        type = 0x61;
      }
      else if ((((((type == 0x35) || (type == 0x40)) || (type == 0x4f)) ||
                ((type == 0x42 || (type == 0x46)))) || (type == 0x4c)) ||
              (((type == 0x4d || (type == 0x24)) ||
               ((type == 0x2c || (((type == 0x7d || (type == 0x2e)) || (type == 0x7b)))))))) {
        if (((((type == 0x41) || (type == 0x39)) ||
             ((type == 0x38 || (((type == 0x30 || (type == 0x42)) || (type == 0x4c)))))) &&
            ((((type != 0x41 && (type != 0x39)) && (type != 0x38)) &&
             ((type != 0x30 && (type != 0x4f)))))) &&
           (((type != 0x46 && ((type != 0x4c && (type != 0x4d)))) && (type != 0x7b)))) {
          type = 0x67;
        }
        else {
          type = 99;
        }
      }
      else {
        type = 99;
      }
      break;
    case 0x26:
      type = 0x6e;
      break;
    case 0x2b:
    case 0x5e:
      type = 0x74;
      break;
    case 0x2d:
    case 0x44:
    case 0x52:
      type = 0x72;
      break;
    case 0x3d:
    case 0x4b:
      type = 0x69;
      break;
    case 0x59:
      type = 0x78;
    }
  }
  iVar1 = tolower(type);
  return (char)iVar1;
}

int brickIsCompute(unsigned int type)
{
  int iVar1;
  
  iVar1 = 0;
  if (((((((type == 0x43) || (type == 0x33)) || (type == 0x35)) ||
        (((type == 0x34 || (type == 0x41)) || ((type == 0x36 || ((type == 0x39 || (type == 0x37)))))
         ))) || ((type == 0x38 || (((type == 0x30 || (type == 0x51)) || (type == 0x40)))))) ||
      (((type == 0x4f || (type == 0x42)) ||
       (((type == 0x46 || ((type == 0x4c || (type == 0x4d)))) || (type == 0x24)))))) ||
     ((((type == 0x2c || (type == 0x7d)) || (type == 0x2e)) || (type == 0x7b)))) {
    iVar1 = 1;
  }
  return iVar1;
}
