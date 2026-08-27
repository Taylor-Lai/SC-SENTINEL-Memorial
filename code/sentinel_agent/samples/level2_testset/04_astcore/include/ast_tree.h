#ifndef AST_TREE_H
#define AST_TREE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    NODE_PROGRAM,
    NODE_FUNCTION,
    NODE_BLOCK,
    NODE_ASSIGN,
    NODE_BINOP,
    NODE_UNOP,
    NODE_CALL,
    NODE_IDENT,
    NODE_NUMBER,
    NODE_STRING,
    NODE_IF,
    NODE_WHILE,
    NODE_RETURN,
} node_type_t;

#define MAX_CHILDREN 16

typedef struct ast_node {
    node_type_t      type;
    char            *name;       

    double           number;     

    struct ast_node *children[MAX_CHILDREN];
    int              child_count;

    struct ast_node *parent;     

    int              ref_count;  

} ast_node_t;

ast_node_t *ast_node_new(node_type_t type, const char *name);
void        ast_node_free(ast_node_t *node);          

int         ast_node_add_child(ast_node_t *parent, ast_node_t *child);
ast_node_t *ast_node_detach_child(ast_node_t *parent, int index);
void        ast_node_replace(ast_node_t *parent, int index,
                             ast_node_t *new_child);  

ast_node_t *ast_parse_expr(const char *src, size_t len);
ast_node_t *ast_parse_stmt(const char *src, size_t len);
ast_node_t *ast_parse_program(const char *src, size_t len);
void        ast_print(const ast_node_t *node, int indent);
int         ast_node_count(const ast_node_t *node);

int         ast_serialize(const ast_node_t *node, char *out, size_t max);
ast_node_t *ast_deserialize(const char *buf, size_t len);  

#endif 

