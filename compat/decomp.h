/*
 * decomp.h: types and helper macros that Ghidra's decompiler output uses.
 *
 * Every bootstrapped .c includes this. As a file is cleaned up into real C,
 * drop its include; the goal is for nothing to need it.
 */
#ifndef DECOMP_H
#define DECOMP_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef unsigned char byte;
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef unsigned char undefined;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined3;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef void code(void);

/* CONCATxy(a, b): a (x bytes) is the high part, b (y bytes) the low part */
#define CONCAT11(a, b) ((uint16_t)(((uint16_t)(uint8_t)(a) << 8) | (uint8_t)(b)))
#define CONCAT12(a, b) ((uint32_t)(((uint32_t)(uint8_t)(a) << 16) | (uint16_t)(b)))
#define CONCAT13(a, b) ((uint32_t)(((uint32_t)(uint8_t)(a) << 24) | ((uint32_t)(b) & 0xffffff)))
#define CONCAT21(a, b) ((uint32_t)(((uint32_t)(uint16_t)(a) << 8) | (uint8_t)(b)))
#define CONCAT22(a, b) ((uint32_t)(((uint32_t)(uint16_t)(a) << 16) | (uint16_t)(b)))
#define CONCAT31(a, b) ((uint32_t)(((uint32_t)(a) << 8) | (uint8_t)(b)))
#define CONCAT44(a, b) ((uint64_t)(((uint64_t)(uint32_t)(a) << 32) | (uint32_t)(b)))
/* SUBxy(v, n): y bytes of the x-byte value v, starting at byte n */
#define SUB41(v, n) ((uint8_t)((uint32_t)(v) >> ((n) * 8)))
#define SUB42(v, n) ((uint16_t)((uint32_t)(v) >> ((n) * 8)))
#define SUB21(v, n) ((uint8_t)((uint16_t)(v) >> ((n) * 8)))
#define SUB81(v, n) ((uint8_t)((uint64_t)(v) >> ((n) * 8)))
#define SUB84(v, n) ((uint32_t)((uint64_t)(v) >> ((n) * 8)))
#define ZEXT14(v) ((uint32_t)(uint8_t)(v))
#define ZEXT24(v) ((uint32_t)(uint16_t)(v))
#define ZEXT48(v) ((uint64_t)(uint32_t)(v))
#define SEXT14(v) ((int32_t)(int8_t)(v))
#define SEXT24(v) ((int32_t)(int16_t)(v))
#define SEXT48(v) ((int64_t)(int32_t)(v))

#endif /* DECOMP_H */
