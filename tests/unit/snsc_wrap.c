/*
 * One implementation of l3/IRouter/IRouterOS.c (IMPL) with its functions
 * renamed PREFIX_*, for tests/unit/snsc_test.c.
 */
#define CAT(a, b) CAT2(a, b)
#define CAT2(a, b) a##b
#define IRouterConnectOS    CAT(PREFIX, _ConnectOS)
#define IRouterDisconnectOS CAT(PREFIX, _DisconnectOS)
#define IRouterRequestOS    CAT(PREFIX, _RequestOS)
#define IRouterResponseOS   CAT(PREFIX, _ResponseOS)
#define IRouterEventOS      CAT(PREFIX, _EventOS)
#define IRouterGetPacketOS  CAT(PREFIX, _GetPacketOS)
#include IMPL

int CAT(PREFIX, _pipe_out)(int fd, unsigned char *pptr, int plen)
{
  return pipe_out(fd, pptr, plen);
}

int CAT(PREFIX, _pipe_in)(int fd, unsigned char **pptr, int plen)
{
  return pipe_in(fd, pptr, plen);
}
