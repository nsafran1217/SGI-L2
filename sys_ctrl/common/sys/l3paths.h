/*
 * sys_ctrl/common/sys/l3paths.h
 *
 * New in the reconstruction (not part of SGI's tree). The original tools
 * hardcoded these paths; each can now be set with an environment variable.
 * Unset, every function returns the original path, so behaviour is unchanged.
 *
 *   SGI_L2_NVRAM       NVRAM file          "./.l2_NVRAM" (cwd), ".N" appended for --copy N
 *   SGI_L3_SOCKET_DIR  UNIX_xxxx sockets   "/usr/tmp", or "/tmp" if /usr/tmp does not exist
 *   SGI_L3_DEV_DIR     device nodes        "/dev" (sgil1_cs, sgil1_N, ttyS1)
 *   SGI_L3_MTRACE_DIR  --mtrace output     "/tmp"
 */
#ifndef SYS_CTRL_COMMON_SYS_L3PATHS_H
#define SYS_CTRL_COMMON_SYS_L3PATHS_H

/* NVRAM file for an l2 whose network ports are biased by port_bias (--copy). */
const char *l3path_nvram(int port_bias);
const char *l3path_socket_dir(void);
const char *l3path_dev_dir(void);
const char *l3path_mtrace_dir(void);

/* Device node <dev dir>/<name>, in a static buffer per call site's argument. */
const char *l3path_dev(const char *name);

#endif /* SYS_CTRL_COMMON_SYS_L3PATHS_H */
