# Intentional differences from the original binaries

Behaviour that differs from SGI's 1.62.0 binaries because the original relied
on something modern systems no longer have. (SGI's own bugs, kept or fixed,
are in ORIGINAL_BUGS.md.)

| Where | Difference | Why |
|---|---|---|
| `common/sys/minfo.c` (`l2` "minfo" commands) | Allocation tracking records nothing. The commands still run, and the `mallinfo()` statistics still print. | It installs glibc's `__malloc_hook` family, which glibc 2.34 removed. With an older glibc the original code path is compiled in unchanged. |
| `common/sys/sysutils.h` `struct _sem_t`, `struct _queue_t` | Bigger than the original (48 bytes). | They embed `pthread_mutex_t`/`pthread_cond_t`, which are bigger in modern glibc than in glibc 2.1.3. Both are in-memory only, so nothing depends on the old layout. |
