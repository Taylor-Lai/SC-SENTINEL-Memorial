

#include "ast_tree.h"
#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT (1 << 16)

int main(int argc, char *argv[])
{
    FILE *fp = stdin;
    if (argc >= 2) {
        fp = fopen(argv[1], "rb");
        if (!fp) { perror("fopen"); return 1; }
    }

    char *buf = (char *)malloc(MAX_INPUT);
    if (!buf) return 1;
    size_t len = fread(buf, 1, MAX_INPUT - 1, fp);
    buf[len] = '\0';
    if (argc >= 2) fclose(fp);

    

    ast_node_t *tree = ast_deserialize(buf, len);
    if (tree) {
        ast_print(tree, 0);
        ast_node_free(tree);  

    }

    

    ast_node_t *expr = ast_parse_expr(buf, len);
    if (expr) {
        ast_print(expr, 0);
        ast_node_free(expr);
    }

    free(buf);
    return 0;
}
