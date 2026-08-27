#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define JSON_MAX_DEPTH   32
#define JSON_STRING_INIT 64

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT,
    JSON_ERROR
} json_type_t;

typedef struct json_value {
    json_type_t          type;
    char                *key;
    union {
        double               number;
        int                  boolean;
        char                *string;
        struct json_value   *children;  

    } v;
    struct json_value   *next;          

} json_value_t;

typedef struct {
    const char  *src;
    size_t       pos;
    size_t       len;
    int          depth;
    char        *error;
} json_ctx_t;

json_value_t *json_parse(const char *input, size_t len);
void          json_free(json_value_t *val);
const char   *json_get_string(const json_value_t *val, const char *key);
double        json_get_number(const json_value_t *val, const char *key);
void          json_print(const json_value_t *val, int indent);

json_value_t *json_parse_value(json_ctx_t *ctx);
char         *json_parse_string(json_ctx_t *ctx);   

json_value_t *json_parse_array(json_ctx_t *ctx);
json_value_t *json_parse_object(json_ctx_t *ctx);

#endif 

