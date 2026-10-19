/*
 * sys_ctrl/l3/l2api/http.h
 *
 * New in the modern tree: the HTTP/1.1 side of l2api, with WebSockets
 * (RFC 6455) and server-sent events. See http.c.
 */

#ifndef SYS_CTRL_L3_L2API_HTTP_H
#define SYS_CTRL_L3_L2API_HTTP_H

#include <stddef.h>

#define HTTP_MAX_HEAD   16384   /* request line and headers */
#define HTTP_MAX_BODY   65536

/* http_conn.state */
enum {
    HTTP_READING = 0,           /* the request */
    HTTP_REPLYING,              /* the response; closed once it is out */
    HTTP_WEBSOCKET,             /* frames both ways */
    HTTP_EVENTS,                /* server-sent events, until the client goes */
    HTTP_DEAD,                  /* to be closed (by its owner) */
};

typedef struct http_conn {
    int fd;
    int state;
    long since;                 /* when it was accepted, or its response queued (time()) */
    char in[HTTP_MAX_HEAD + HTTP_MAX_BODY + 1];
    size_t inlen;
    char *out;                  /* what is still to be sent */
    size_t outlen, outcap;
    /* the request */
    char method[16];
    char path[512];
    size_t head_len;            /* request line and headers, with the blank line */
    size_t body_len;            /* Content-Length */
    char ws_key[64];            /* Sec-WebSocket-Key, for an upgrade */
    int upgrade;                /* "Upgrade: websocket" */
    /* the user's */
    int relay;                  /* l2api: the console socket of a WebSocket, or -1 */
    struct http_conn *next;
} http_conn;

int http_listen(const char *spec);
http_conn *http_accept(int listen_fd);
int http_read(http_conn *c);
int http_request_done(http_conn *c);
const char *http_body(http_conn *c);
void http_write(http_conn *c, const void *data, size_t len);
int http_flush(http_conn *c);
void http_reply(http_conn *c, int code, const char *type, const char *body, size_t len);
void http_close(http_conn *c);

int ws_accept(http_conn *c);
void ws_send(http_conn *c, int opcode, const void *data, size_t len);
typedef void (*ws_message_fn)(http_conn *c, int opcode, const unsigned char *data, size_t len);
int ws_read_frames(http_conn *c, ws_message_fn fn);

void events_start(http_conn *c);
void events_send(http_conn *c, const char *event, const char *data);

/* WebSocket opcodes */
#define WS_TEXT     1
#define WS_BINARY   2
#define WS_CLOSE    8
#define WS_PING     9
#define WS_PONG     10

#endif /* SYS_CTRL_L3_L2API_HTTP_H */
