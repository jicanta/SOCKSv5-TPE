#ifndef HELLO_PARSER_H
#define HELLO_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"
#include "socks5nio.h"  

enum hello_state {
    HELLO_VERSION,    
    HELLO_NMETHODS,   
    HELLO_METHODS,    
    HELLO_DONE,       
    HELLO_ERROR       
};

struct hello_parser {
    enum hello_state state;  
    uint8_t remaining;       
    void *data;              
    void (*on_authentication_method)(struct hello_parser *p, const uint8_t method);  // Callback
};

void hello_parser_init(struct hello_parser *p);
enum hello_state hello_consume(buffer *b, struct hello_parser *p, bool *error);
bool hello_is_done(const enum hello_state st, bool *error);
int hello__build_reply(buffer *b, const uint8_t method);

#endif