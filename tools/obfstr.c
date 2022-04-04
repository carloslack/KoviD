#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void convert_up(char *s)
{
    int i;
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] >= 'a' && s[i] <= 'z') {
            s[i] = s[i] - 32;
        } else if (s[i] == '-')
            s[i] = '_';
        else if (s[i] == '.')
            s[i] = '_';
        else if (s[i] == ' ')
            s[i] = '_';
    }
}

int main(int argc, char **argv) {
    int i,len;
    char *str, *up;
    if (argc < 2) {
        printf("Use: %s <string>\n", argv[0]);
        exit(0);
    }

    str = argv[1];
    up = strdup(str);
    convert_up(up);
    printf ("#define _OBF_%s  \"", up);
    for (i = 0, len = strlen(str); i < len; ++i, ++str)
        printf("\\%03o%c", i, *str);
    printf("\"\n");

    free(up);
    return 0;
}
