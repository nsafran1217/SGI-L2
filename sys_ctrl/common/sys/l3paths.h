/*
 * sys_ctrl/common/sys/l3paths.h
 *
 * New in the reconstruction (not part of SGI's tree). The original tools
 * hardcoded these paths; each can now be set with an environment variable.
 *
 *   SGI_L2_CONFIG      l2's settings file  "$STATE_DIRECTORY/l2.conf" (systemd), else "./l2.conf";
 *                      ".N" appended for --copy N (l2's -c overrides; l2.log is next to it)
 *   SGI_L3_SOCKET_DIR  UNIX_xxxx sockets   "/usr/tmp", or "/tmp" if /usr/tmp does not exist
 */
#ifndef SYS_CTRL_COMMON_SYS_L3PATHS_H
#define SYS_CTRL_COMMON_SYS_L3PATHS_H

/* settings file for an l2 whose network ports are biased by port_bias (--copy) */
const char *l3path_settings(int port_bias);
const char *l3path_socket_dir(void);


#endif /* SYS_CTRL_COMMON_SYS_L3PATHS_H */
