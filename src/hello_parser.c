#include "hello_parser.h"
#include <string.h>  

void hello_parser_init(struct hello_parser *p) {
    memset(p, 0, sizeof(*p));  
    p->state = HELLO_VERSION; 
}

enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *error) {
    *error = false;

    while (buffer_can_read(b)) {
        const uint8_t c = buffer_read(b);
        switch (p->state) {
            case HELLO_VERSION:
                if (c != SOCKS_VERSION) {
                    p->state = HELLO_ERROR;
                    *error = true;
                } else {
                    p->state = HELLO_NMETHODS;
                }
                break;
            case HELLO_NMETHODS:
                p->remaining = c;
                if (p->remaining == 0) {
                    p->state = HELLO_DONE;
                } else {
                    p->state = HELLO_METHODS;
                }
                break;
            case HELLO_METHODS:
                if (p->on_authentication_method != NULL) {
                    p->on_authentication_method(p, c);  // llama callback
                }
                if (--p->remaining == 0) {
                    p->state = HELLO_DONE;
                }
                break;
            case HELLO_DONE:
            case HELLO_ERROR:
                return p->state;  
        }
        if (p->state == HELLO_ERROR) {
            *error = true;
            return HELLO_ERROR;
        }
    }
    return p->state;
}

bool hello_is_done(const enum hello_state st, bool *error) {
    if (st == HELLO_DONE) {
        if (error != NULL) *error = false;
        return true;
    }
    if (st == HELLO_ERROR) {
        if (error != NULL) *error = true;
    }
    return false;
}

int hello__build_reply(buffer *b, const uint8_t method) {
    size_t n;
    uint8_t *ptr = buffer_write_ptr(b, &n);
    if (n < 2) {
        return -1; 
    }
    *ptr++ = SOCKS_VERSION;
    *ptr++ = method;
    buffer_write_adv(b, 2);
    return 2;
}