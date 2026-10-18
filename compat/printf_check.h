/*
 * printf_check.h: included in every C file (-include, Makefile).
 *
 * The build turns off gcc's builtin fprintf (-fno-builtin-fprintf): l2
 * replaces fprintf (smp.c), and gcc must not turn calls into fputs() or
 * fwrite() behind its back. Without the builtin gcc no longer checks
 * fprintf formats, and glibc's declaration has no format attribute, so it
 * gets one here.
 */
#ifndef PRINTF_CHECK_H
#define PRINTF_CHECK_H

/* (no #include: a file's own feature macros must come before the system
 * headers; glibc's FILE is struct _IO_FILE) */
struct _IO_FILE;
extern int fprintf(struct _IO_FILE *__restrict __stream, const char *__restrict __format, ...)
    __attribute__((format(printf, 2, 3)));

#endif /* PRINTF_CHECK_H */
