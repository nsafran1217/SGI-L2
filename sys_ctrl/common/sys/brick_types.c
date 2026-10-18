/*
 * sys_ctrl/common/sys/brick_types.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/brick_types.c
 *
 * Brick types. An L1 reports its brick's type as a character ('C' for an
 * IP35 C-brick, 'R' for a router, ...); these convert between that, the
 * names the commands accept, display names and the one-letter class
 * ('c' compute, 'r' router, 'i' I/O, 'p' PCI, ...).
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include "brick_types.h"

#define BRICK_UNKNOWN '?'

/* types given as themselves, one letter (upper or lower case) */
static const char letter_types[] = "#%&=AGIJKNPRXY";

/* types given by name */
static const struct {
  const char *name;
  unsigned char type;
} named_types[] = {
  { "ip35", 'C' },
  { "ip37", '3' },
  { "ip45", '4' },
  { "ip41", '5' },
  { "twister", '6' },
  { "vortix", '@' },
  { "opus", 'O' },
  { "gemini", 'B' },
  { "dorado", 'L' },
  { "ip69", '$' },
  { "191010", '.' },
  { "1932", ',' },
  { "1955", '}' },
  { "drouter", '-' },
  { "ip71", '{' },
  { "nl4r", 'D' },
  { "nl4s", 'S' },
  { "T1", '1' },
  { "T2", '2' },
  { "T", 'T' },
};

/* display names; other types show as themselves */
static const struct {
  unsigned char type;
  const char *name;
} type_names[] = {
  { '#', "PX" },
  { '$', "C (IP69 HACK, 1932 Chassis)" },
  { '%', "PE" },
  { '&', "P0 N" },
  { '+', "Athena" },
  { ',', "1932 Chassis" },
  { '-', "Quad Dense Router" },
  { '.', "191010 Chassis" },
  { '0', "CGN Voyager" },
  { '3', "C (IP37)" },
  { '4', "C (IP45)" },
  { '5', "C (IP41)" },
  { '6', "C (Twister)" },
  { '7', "Chimera Server" },
  { '8', "Chimera Blade" },
  { '9', "Chimera WS" },
  { '=', "IX" },
  { '?', "Unknown" },
  { '@', "C (Vortix)" },
  { 'B', "Gemini" },
  { 'C', "C (IP35)" },
  { 'D', "NL4R" },
  { 'E', "2UPX" },
  { 'F', "Opus TIO" },
  { 'J', "PA" },
  { 'K', "IA" },
  { 'L', "Dorado" },
  { 'M', "C (IP67)" },
  { 'O', "Opus" },
  { 'Q', "Rackmount WS" },
  { 'S', "NL4 Snooper" },
  { 'V', "CG Voyager" },
  { 'Y', "X2" },
  { '^', "TIO Test Card" },
  { '{', "IP71" },
  { '}', "1955 Chassis" },
};

/* the compute bricks (those with CPUs) */
static const char compute_types[] = "C354A6978Q0@OBFLM$,}.{";

/* the type a command names: one of the letters, or a name; '?' if neither */
unsigned int brickConvertString(char *sptr)
{
  unsigned int i;
  int c;

  if (strlen(sptr) == 1) {
    c = toupper((unsigned char)*sptr);
    return strchr(letter_types,c) != NULL ? (unsigned int)c : BRICK_UNKNOWN;
  }
  for (i = 0; i < sizeof(named_types) / sizeof(named_types[0]); i++)
    if (strcmp(sptr,named_types[i].name) == 0)
      return named_types[i].type;
  return BRICK_UNKNOWN;
}

/* the display name (a static buffer) */
char *brickConvertType(unsigned int type)
{
  static char buff[32];         /* ORIGINAL BUG: 16 in the original, which "C (IP69 HACK, 1932 Chassis)" overflowed */
  unsigned int i;

  for (i = 0; i < sizeof(type_names) / sizeof(type_names[0]); i++)
    if (type == type_names[i].type)
      return strcpy(buff,type_names[i].name);
  sprintf(buff,"%c",type);
  return buff;
}

/* the one-letter class */
char brickTypeToChar(unsigned int type)
{
  switch (type) {
  case '#':
  case '%':
  case 'J':
    return 'p';
  case '&':
    return 'n';
  case '+':
  case '^':
    return 't';
  case '-':
  case 'D':
  case 'R':
    return 'r';
  case '=':
  case 'K':
    return 'i';
  case 'Y':
    return 'x';
  case 'A':
    return 'a';
  case 'B':                     /* Gemini */
    return 'g';
  }
  if (brickIsCompute(type))
    return 'c';
  return tolower(type);
}

int brickIsCompute(unsigned int type)
{
  return type != 0 && type < 0x100 && strchr(compute_types,type) != NULL;
}
