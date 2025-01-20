// This file is a user-space loader that attaches an eBPF socket_filter_prog
// to a raw AF_PACKET socket. It periodically appends JSON "snapshot" objects
// into a single array in /tmp/ebpf_kovid.json. The JSON is valid from start to
// finish if the program is killed normally (SIGINT, SIGTERM), because we close
// the array.
//
// Usage example:
//   1) Place socket_filter_bpf.o in /usr/bin/socket_filter_bpf.o
//   2) Launch: python3 -m http.server 8080 --bind 127.0.0.1
//   3) wget http://127.0.0.1:8080/
//   4) sudo ./ebpf-kovid
//   5) tail /tmp/ebpf_kovid.json to see the array updating.

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
static FILE *fp = NULL;    // File pointer to /tmp/ebpf_kovid.json
static int snapshot_count = 0; // Keep track of how many snapshots we've written

/* We'll install a signal handler so we can close the JSON array gracefully. */
static void cleanup_and_exit(int sig)
{
    if (fp) {
        // Close the JSON array
        fprintf(fp, "\n]\n");
        fclose(fp);
        fp = NULL;
    }

    if (sock_fd >= 0) close(sock_fd);
    if (obj) bpf_object__close(obj);

    fprintf(stderr, "\nCaught signal %d. Exiting.\n", sig);
    exit(0);
}

int main(int argc, char **argv)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL, *snippet_map = NULL;
    int err;

    // 1) Setup signal handlers to clean up
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

    // 3) Find the eBPF program
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

    // 4) Find the "port_count_map"
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
        fprintf(stderr, "ERROR: couldn't find map '%s'\n",
                http_snippet_map_name);
        goto cleanup;
    }
    snippet_map_fd = bpf_map__fd(snippet_map);
    if (snippet_map_fd < 0) {
        fprintf(stderr, "ERROR: bpf_map__fd(%s) failed\n",
                http_snippet_map_name);
        goto cleanup;
    }

    // 6) Create a raw packet socket and attach eBPF
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) {
        perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)");
        goto cleanup;
    }
    err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF,
                     &prog_fd, sizeof(prog_fd));
    if (err) {
        perror("setsockopt(SO_ATTACH_BPF)");
        goto cleanup;
    }

    // 7) Open /tmp/ebpf_kovid.json. Let's TRUNCATE it at start for fresh data.
    fp = fopen("/tmp/ebpf_kovid.json", "w");
    if (!fp) {
        fprintf(stderr, "ERROR: Could not open /tmp/ebpf_kovid.json for writing.\n");
        goto cleanup;
    }

    // Start a single JSON array
    fprintf(fp, "[\n");
    fflush(fp);

    // 8) Periodically read counters & snippet, log JSON
    __u16 ports[2] = { 22, 443 };

    while (1) {
        // If not the first snapshot, add a comma to separate objects
        if (snapshot_count > 0) {
            fprintf(fp, ",\n");
        }

        // Begin an object
        fprintf(fp, "{\n  \"snapshot\": [\n");

        // (a) port counters
        for (int i = 0; i < 2; i++) {
            __u64 value = 0;
            if (bpf_map_lookup_elem(map_fd, &ports[i], &value) == 0) {
                // Print a JSON array element
                fprintf(fp,
                        "    { \"port\": %u, \"packets\": %llu }%s\n",
                        ports[i], value, (i == 0 ? "," : ""));
            } else {
                fprintf(fp,
                        "    { \"port\": %u, \"packets\": 0 }%s\n",
                        ports[i], (i == 0 ? "," : ""));
            }
        }

        fprintf(fp, "  ],\n"); // close the snapshot array

        // (b) optional HTTP snippet
        {
            __u32 key = 0;
            struct http_snippet snippet;
            memset(&snippet, 0, sizeof(snippet));

            if (bpf_map_lookup_elem(snippet_map_fd, &key, &snippet) == 0) {
                if (snippet.used == 1) {
                    fprintf(fp, "  \"http_snippet\": \"");
                    for (int i = 0; i < HTTP_MAX_BYTES; i++) {
                        unsigned char c = snippet.data[i];
                        // ASCII printable range roughly 32..126
                        if (c >= 32 && c <= 126) {
                            fputc(c, fp);
                        } else {
                            fputc('.', fp);
                        }
                    }
                    fprintf(fp, "\",\n");
                    // Mark snippet used=0 so we don't re-print
                    snippet.used = 0;
                    bpf_map_update_elem(snippet_map_fd, &key, &snippet,
                                        BPF_ANY);
                } else {
                    // No snippet
                    fprintf(fp, "  \"http_snippet\": null,\n");
                }
            } else {
                fprintf(fp, "  \"http_snippet\": null,\n");
            }
        }

        fprintf(fp, "  \"note\": \"another snapshot\"\n}\n"); // end object
        fflush(fp);

        snapshot_count++;
        sleep(5);
    }

cleanup:
    if (fp) {
        // If we exit the loop or error out, close the array properly
        fprintf(fp, "\n]\n");
        fclose(fp);
        fp = NULL;
    }
    if (sock_fd >= 0) close(sock_fd);
    if (obj) bpf_object__close(obj);
    return 0;
}
