

#include "json_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void skip_whitespace(json_ctx_t *ctx)
{
    while (ctx->pos < ctx->len &&
           (ctx->src[ctx->pos] == ' '  ||
            ctx->src[ctx->pos] == '\t' ||
            ctx->src[ctx->pos] == '\r' ||
            ctx->src[ctx->pos] == '\n'))
        ctx->pos++;
}

static int peek(const json_ctx_t *ctx)
{
    if (ctx->pos >= ctx->len) return -1;
    return (unsigned char)ctx->src[ctx->pos];
}

static int advance(json_ctx_t *ctx)
{
    if (ctx->pos >= ctx->len) return -1;
    return (unsigned char)ctx->src[ctx->pos++];
}

static json_value_t *alloc_value(json_type_t type)
{
    json_value_t *v = (json_value_t *)calloc(1, sizeof(json_value_t));
    if (v) v->type = type;
    return v;
}

static int encode_utf8(unsigned int cp, char *out)
{
    if (cp <= 0x7F) {
        out[0] = (char)cp;
        return 1;
    } else if (cp <= 0x7FF) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp <= 0xFFFF) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    } else {
        

        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6)  & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
}

static unsigned int parse_hex4(const char *s)
{
    unsigned int v = 0;
    for (int i = 0; i < 4; i++) {
        v <<= 4;
        char c = s[i];
        if      (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
    }
    return v;
}

char *json_parse_string(json_ctx_t *ctx)
{
    if (peek(ctx) != '"') return NULL;
    advance(ctx); 

    

    size_t buf_size = strlen(ctx->src + ctx->pos) + 1; 

    char  *buf      = (char *)malloc(buf_size);
    if (!buf) return NULL;

    size_t out = 0;

    while (ctx->pos < ctx->len) {
        int c = advance(ctx);
        if (c == '"') {
            buf[out] = '\0';
            return buf;
        }
        if (c != '\\') {
            buf[out++] = (char)c;
            continue;
        }

        

        int esc = advance(ctx);
        switch (esc) {
        case '"':  buf[out++] = '"';  break;
        case '\\': buf[out++] = '\\'; break;
        case '/':  buf[out++] = '/';  break;
        case 'b':  buf[out++] = '\b'; break;
        case 'f':  buf[out++] = '\f'; break;
        case 'n':  buf[out++] = '\n'; break;
        case 'r':  buf[out++] = '\r'; break;
        case 't':  buf[out++] = '\t'; break;
        case '0':  buf[out++] = '\0'; break; 

        case 'u': {
            if (ctx->pos + 4 > ctx->len) goto error;
            unsigned int cp = parse_hex4(ctx->src + ctx->pos);
            ctx->pos += 4;

            

            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (ctx->pos + 6 <= ctx->len &&
                    ctx->src[ctx->pos]   == '\\' &&
                    ctx->src[ctx->pos+1] == 'u') {
                    ctx->pos += 2;
                    unsigned int low = parse_hex4(ctx->src + ctx->pos);
                    ctx->pos += 4;
                    if (low >= 0xDC00 && low <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    }
                }
            }

            

            out += encode_utf8(cp, buf + out);
            break;
        }
        default:
            buf[out++] = (char)esc;
        }
    }

error:
    free(buf);
    return NULL;
}

static json_value_t *json_parse_number(json_ctx_t *ctx)
{
    size_t start = ctx->pos;
    if (peek(ctx) == '-') advance(ctx);
    while (ctx->pos < ctx->len && isdigit((unsigned char)ctx->src[ctx->pos]))
        ctx->pos++;
    if (peek(ctx) == '.') {
        advance(ctx);
        while (ctx->pos < ctx->len && isdigit((unsigned char)ctx->src[ctx->pos]))
            ctx->pos++;
    }
    if (peek(ctx) == 'e' || peek(ctx) == 'E') {
        advance(ctx);
        if (peek(ctx) == '+' || peek(ctx) == '-') advance(ctx);
        while (ctx->pos < ctx->len && isdigit((unsigned char)ctx->src[ctx->pos]))
            ctx->pos++;
    }
    char tmp[64] = {0};
    size_t numlen = ctx->pos - start;
    if (numlen >= sizeof(tmp)) numlen = sizeof(tmp) - 1;
    memcpy(tmp, ctx->src + start, numlen);

    json_value_t *v = alloc_value(JSON_NUMBER);
    if (v) v->v.number = atof(tmp);
    return v;
}

json_value_t *json_parse_value(json_ctx_t *ctx)
{
    skip_whitespace(ctx);
    if (ctx->pos >= ctx->len) return NULL;
    if (ctx->depth >= JSON_MAX_DEPTH) return NULL;

    ctx->depth++;
    json_value_t *result = NULL;
    int c = peek(ctx);

    if (c == '"') {
        char *s = json_parse_string(ctx);
        if (!s) { ctx->depth--; return NULL; }
        result = alloc_value(JSON_STRING);
        if (result) result->v.string = s;
        else free(s);
    } else if (c == '{') {
        result = json_parse_object(ctx);
    } else if (c == '[') {
        result = json_parse_array(ctx);
    } else if (c == 't') {
        if (ctx->pos + 4 <= ctx->len &&
            strncmp(ctx->src + ctx->pos, "true", 4) == 0) {
            ctx->pos += 4;
            result = alloc_value(JSON_BOOL);
            if (result) result->v.boolean = 1;
        }
    } else if (c == 'f') {
        if (ctx->pos + 5 <= ctx->len &&
            strncmp(ctx->src + ctx->pos, "false", 5) == 0) {
            ctx->pos += 5;
            result = alloc_value(JSON_BOOL);
            if (result) result->v.boolean = 0;
        }
    } else if (c == 'n') {
        if (ctx->pos + 4 <= ctx->len &&
            strncmp(ctx->src + ctx->pos, "null", 4) == 0) {
            ctx->pos += 4;
            result = alloc_value(JSON_NULL);
        }
    } else if (c == '-' || isdigit(c)) {
        result = json_parse_number(ctx);
    }

    ctx->depth--;
    return result;
}

json_value_t *json_parse_array(json_ctx_t *ctx)
{
    if (peek(ctx) != '[') return NULL;
    advance(ctx);

    json_value_t *arr  = alloc_value(JSON_ARRAY);
    json_value_t *tail = NULL;

    skip_whitespace(ctx);
    if (peek(ctx) == ']') { advance(ctx); return arr; }

    while (ctx->pos < ctx->len) {
        json_value_t *elem = json_parse_value(ctx);
        if (!elem) { json_free(arr); return NULL; }

        if (!arr->v.children) {
            arr->v.children = elem;
        } else {
            tail->next = elem;
        }
        tail = elem;

        skip_whitespace(ctx);
        if (peek(ctx) == ']') { advance(ctx); return arr; }
        if (peek(ctx) != ',') { json_free(arr); return NULL; }
        advance(ctx);
        skip_whitespace(ctx);
    }
    json_free(arr);
    return NULL;
}

json_value_t *json_parse_object(json_ctx_t *ctx)
{
    if (peek(ctx) != '{') return NULL;
    advance(ctx);

    json_value_t *obj  = alloc_value(JSON_OBJECT);
    json_value_t *tail = NULL;

    skip_whitespace(ctx);
    if (peek(ctx) == '}') { advance(ctx); return obj; }

    while (ctx->pos < ctx->len) {
        skip_whitespace(ctx);
        if (peek(ctx) != '"') { json_free(obj); return NULL; }

        char *key = json_parse_string(ctx);
        if (!key) { json_free(obj); return NULL; }

        skip_whitespace(ctx);
        if (peek(ctx) != ':') { free(key); json_free(obj); return NULL; }
        advance(ctx);
        skip_whitespace(ctx);

        json_value_t *val = json_parse_value(ctx);
        if (!val) { free(key); json_free(obj); return NULL; }
        val->key = key;

        if (!obj->v.children) {
            obj->v.children = val;
        } else {
            tail->next = val;
        }
        tail = val;

        skip_whitespace(ctx);
        if (peek(ctx) == '}') { advance(ctx); return obj; }
        if (peek(ctx) != ',') { json_free(obj); return NULL; }
        advance(ctx);
    }
    json_free(obj);
    return NULL;
}

json_value_t *json_parse(const char *input, size_t len)
{
    if (!input || len == 0) return NULL;
    json_ctx_t ctx = { .src = input, .pos = 0, .len = len, .depth = 0 };
    skip_whitespace(&ctx);
    return json_parse_value(&ctx);
}

void json_free(json_value_t *val)
{
    if (!val) return;
    json_free(val->next);
    free(val->key);
    switch (val->type) {
    case JSON_STRING: free(val->v.string); break;
    case JSON_ARRAY:
    case JSON_OBJECT: json_free(val->v.children); break;
    default: break;
    }
    free(val);
}

const char *json_get_string(const json_value_t *val, const char *key)
{
    if (!val || val->type != JSON_OBJECT) return NULL;
    for (const json_value_t *c = val->v.children; c; c = c->next)
        if (c->key && strcmp(c->key, key) == 0 && c->type == JSON_STRING)
            return c->v.string;
    return NULL;
}

double json_get_number(const json_value_t *val, const char *key)
{
    if (!val || val->type != JSON_OBJECT) return 0.0;
    for (const json_value_t *c = val->v.children; c; c = c->next)
        if (c->key && strcmp(c->key, key) == 0 && c->type == JSON_NUMBER)
            return c->v.number;
    return 0.0;
}

void json_print(const json_value_t *val, int indent)
{
    if (!val) return;
    for (int i = 0; i < indent; i++) putchar(' ');
    if (val->key) printf("\"%s\": ", val->key);
    switch (val->type) {
    case JSON_NULL:   printf("null\n"); break;
    case JSON_BOOL:   printf("%s\n", val->v.boolean ? "true" : "false"); break;
    case JSON_NUMBER: printf("%g\n", val->v.number); break;
    case JSON_STRING: printf("\"%s\"\n", val->v.string ? val->v.string : ""); break;
    case JSON_ARRAY:
        printf("[\n");
        json_print(val->v.children, indent + 2);
        for (int i = 0; i < indent; i++) putchar(' ');
        printf("]\n");
        break;
    case JSON_OBJECT:
        printf("{\n");
        json_print(val->v.children, indent + 2);
        for (int i = 0; i < indent; i++) putchar(' ');
        printf("}\n");
        break;
    default: break;
    }
    json_print(val->next, indent);
}
