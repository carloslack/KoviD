/*
 * Run this in background, i.e.:
 *
 * ./test &
 * tail -F /tmp/wally.txt
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>

int main(int argc, char **argv) {

    pid_t pid = getpid();
    char p[32+1] = {0};
    FILE *fp;

    snprintf(p, 32, "/tmp/kv.%d", pid);
    fp = fopen(p, "w");
    if (fp) {
        struct timeval tv;
        int x = 0;
        printf("Running %d on %s\n", pid, p);
        while (1) {
            if (!gettimeofday(&tv, NULL)) {
                char buf[64+1] = {0};
                snprintf(buf, 64, "[%d] running %lu", x++, tv.tv_sec);
                fprintf(fp, "%s\n", buf);
                fflush(fp);
                sleep(1);
            }
        }
    }
}
