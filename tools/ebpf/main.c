// ebpf-kovid.c
// 
// A user-space loader that attaches an eBPF socket_filter_prog to a raw
// AF_PACKET socket and logs to /tmp/ebpf_kovid.json as a single JSON array.
//
// Key difference: We attempt a minimal parse of the 64-byte snippet,
// extracting "status", "len", and printing "content" in ASCII.

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *bpf_object_file       = "/usr/bin/socket_filter_bpf.o";
static const char *bpf_prog_section      = "socket";
static const char *bpf_map_name          = "port_count_map";
static const char *http_snippet_map_name = "http_snippet_map";

#define HTTP_MAX_BYTES 64

struct http_snippet {
    unsigned char data[HTTP_MAX_BYTES];
    unsigned int used;
};

static int prog_fd = -1, map_fd = -1, snippet_map_fd = -1;
static int sock_fd = -1;
static struct bpf_object *obj = NULL;
static FILE *fp = NULL;           // logs to /tmp/ebpf_kovid.json
static int snapshot_count = 0;    // how many snapshots we've written

/* On SIGINT or SIGTERM, finalize JSON array and exit. */
static void cleanup_and_exit(int sig)
{
    if (fp) {
        fprintf(fp, "\n]\n"); // close the JSON array
        fclose(fp);
        fp = NULL;
    }
    if (sock_fd >= 0) close(sock_fd);
    if (obj) bpf_object__close(obj);

    fprintf(stderr, "\nCaught signal %d. Exiting.\n", sig);
    exit(0);
}

/*
 * Minimal function to parse snippet:
 * - If starts with "HTTP/1." => parse a status code
 * - Else if starts with "GET ", "POST ", etc => maybe it's a request
 * 
 * Return:
 *   1) status code (or 0 if not found)
 *   2) set *is_request to 1 if we recognized a request method
 *   3) content is always the sanitized ASCII
 */
static int parse_http_snippet(const unsigned char *buf, int buf_len,
                              int *is_request, char *ascii_out, int ascii_out_len)
{
    int status = 0;
    *is_request = 0;

    // 1) Convert snippet to ASCII, replacing non-printables
    //    We'll also do partial parse below
    for (int i = 0; i < buf_len && i < ascii_out_len - 1; i++) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) {
            ascii_out[i] = c;
        } else {
            ascii_out[i] = '.';
        }
    }
    ascii_out[(buf_len < ascii_out_len - 1) ? buf_len : (ascii_out_len - 1)] = '\0';

    // 2) Check if starts with "HTTP/1."
    if (buf_len >= 9 && !memcmp(buf, "HTTP/1.", 7)) {
        // e.g., "HTTP/1.1 200 OK"
        // skip "HTTP/1.x " => 9 chars, then parse next 3 as status
        // see if there's a digit
        if (buf_len >= 13 && buf[8] == ' ') {
            // e.g. "HTTP/1.x 200"
            // the status code is at buf[9..11]
            if (buf[9] >= '0' && buf[9] <= '9' &&
                buf[10] >= '0' && buf[10] <= '9' &&
                buf[11] >= '0' && buf[11] <= '9')
            {
                int hundreds = (buf[9] - '0') * 100;
                int tens = (buf[10] - '0') * 10;
                int ones = (buf[11] - '0');
                status = hundreds + tens + ones;
            }
        }
    }
    // 3) Else check if "GET ", "POST ", "HEAD ", etc => request
    //    We'll just check "GET " or "POST " for demonstration
    else {
        if (buf_len >= 4 && (!memcmp(buf, "GET ", 4) ||
                             !memcmp(buf, "POST", 4) ||
                             !memcmp(buf, "HEAD", 4))) {
            *is_request = 1;
        }
    }

    return status;
}

int main(int argc, char **argv)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL, *snippet_map = NULL;
    int err;

    // 1) Setup signal handlers
    signal(SIGINT, cleanup_and_exit);
    signal(SIGTERM, cleanup_and_exit);

    // 2) Open and load the BPF object
    obj = bpf_object__open_file(bpf_object_file, NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: bpf_object__open_file(%s) failed\n",
                bpf_object_file);
        return 1;
    }
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: bpf_object__load() failed\n");
        goto cleanup;
    }

    // 3) Find eBPF program
    prog = bpf_object__find_program_by_title(obj, bpf_prog_section);
    if (!prog) {
        fprintf(stderr, "ERROR: couldn't find program section '%s'\n",
                bpf_prog_section);
        goto cleanup;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: bpf_program__fd() failed\n");
        goto cleanup;
    }

    // 4) Find "port_count_map"
    map = bpf_object__find_map_by_name(obj, bpf_map_name);
    if (!map) {
        fprintf(stderr, "ERROR: couldn't find map '%s'\n", bpf_map_name);
        goto cleanup;
    }
    map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: bpf_map__fd(%s) failed\n", bpf_map_name);
        goto cleanup;
    }

    // 5) Find "http_snippet_map"
    snippet_map = bpf_object__find_map_by_name(obj, http_snippet_map_name);
    if (!snippet_map) {
        fprintf(stderr, "ERROR: couldn't find map '%s'\n", http_snippet_map_name);
        goto cleanup;
    }
    snippet_map_fd = bpf_map__fd(snippet_map);
    if (snippet_map_fd < 0) {
        fprintf(stderr, "ERROR: bpf_map__fd(%s) failed\n", http_snippet_map_name);
        goto cleanup;
    }

    // 6) Create a raw packet socket + attach eBPF
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)");
        goto cleanup;
    }
    err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
    if (err) {
        perror("setsockopt(SO_ATTACH_BPF)");
        goto cleanup;
    }

    // 7) Open /tmp/ebpf_kovid.json (truncate existing)
    fp = fopen("/tmp/ebpf_kovid.json", "w");
    if (!fp) {
        fprintf(stderr, "ERROR: Could not open /tmp/ebpf_kovid.json for writing.\n");
        goto cleanup;
    }

    // Start a JSON array
    fprintf(fp, "[\n");
    fflush(fp);

    __u16 ports[2] = {22, 443};

    // 8) Main loop: read counters & snippet every 5s, parse snippet, produce JSON
    while (1) {
        // Separate objects with comma
        if (snapshot_count > 0) {
            fprintf(fp, ",\n");
        }

        fprintf(fp, "{\n  \"snapshot\": [\n");

        // (a) port counters
        for (int i = 0; i < 2; i++) {
            __u64 value = 0;
            if (bpf_map_lookup_elem(map_fd, &ports[i], &value) == 0) {
                fprintf(fp,
                        "    { \"port\": %u, \"packets\": %llu }%s\n",
                        ports[i], value, (i == 0 ? "," : ""));
            } else {
                fprintf(fp,
                        "    { \"port\": %u, \"packets\": 0 }%s\n",
                        ports[i], (i == 0 ? "," : ""));
            }
        }

        fprintf(fp, "  ],\n"); // close snapshot array

        // (b) Check snippet
        {
            __u32 key = 0;
            struct http_snippet snippet;
            memset(&snippet, 0, sizeof(snippet));

            if (bpf_map_lookup_elem(snippet_map_fd, &key, &snippet) == 0) {
                if (snippet.used == 1) {
                    int is_request = 0;
                    int status_code = 0;
                    char ascii_buf[HTTP_MAX_BYTES + 1];
                    int len = HTTP_MAX_BYTES; // we always read 64 bytes if available

                    // parse snippet
                    status_code = parse_http_snippet(snippet.data, len,
                                                     &is_request,
                                                     ascii_buf, sizeof(ascii_buf));

                    // JSON fields: status, len, content
                    // If we found a valid status code, we show it
                    // else null or 0
                    if (status_code > 0) {
                        fprintf(fp, "  \"status\": %d,\n", status_code);
                    } else {
                        fprintf(fp, "  \"status\": null,\n");
                    }

                    fprintf(fp, "  \"len\": %d,\n", len);
                    fprintf(fp, "  \"content\": \"%s\",\n", ascii_buf);

                    // Mark snippet used=0 so we don't re-print
                    snippet.used = 0;
                    bpf_map_update_elem(snippet_map_fd, &key, &snippet,
                                        BPF_ANY);
                } else {
                    // No snippet
                    fprintf(fp, "  \"status\": null,\n");
                    fprintf(fp, "  \"len\": 0,\n");
                    fprintf(fp, "  \"content\": null,\n");
                }
            } else {
                // If snippet lookup fails
                fprintf(fp, "  \"status\": null,\n");
                fprintf(fp, "  \"len\": 0,\n");
                fprintf(fp, "  \"content\": null,\n");
            }
        }

        fprintf(fp, "  \"note\": \"another snapshot\"\n}\n"); // end object
        fflush(fp);

        snapshot_count++;
        sleep(5);
    }

cleanup:
    if (fp) {
        fprintf(fp, "\n]\n");
        fclose(fp);
        fp = NULL;
    }
    if (sock_fd >= 0) close(sock_fd);
    if (obj) bpf_object__close(obj);
    return 0;
}
