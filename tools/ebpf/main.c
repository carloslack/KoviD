// This file is a user-space loader that attaches the socket_filter_prog eBPF
// program to a raw socket (AF_PACKET, SOCK_RAW). It then periodically reads
// and prints packet counters for SSH (port 22) and HTTPS (port 443) traffic,
// as well as retrieving an 8-byte HTTP snippet from http_snippet_map if
// present.

// To test it:
// == Terminal 1:
// $ python3 -m http.server 8080 --bind 127.0.0.1
// == Terminal 2:
// $ wget http://127.0.0.1:8080/
// == Terminal 3:
// $ sudo ./socket_filter_user
//

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char *bpf_object_file = "./socket_filter_bpf.o";
static const char *bpf_map_name = "port_count_map";
static const char *bpf_prog_section = "socket";

static const char *http_snippet_map_name = "http_snippet_map";

#define HTTP_MAX_BYTES 64

struct http_snippet {
  unsigned char data[HTTP_MAX_BYTES];
  unsigned int used;
};

int main(int argc, char **argv) {
  struct bpf_object *obj = NULL;
  struct bpf_program *prog = NULL;
  struct bpf_map *map = NULL, *snippet_map = NULL;
  int prog_fd, map_fd, snippet_map_fd;
  int sock_fd;
  int err;

  // 1) Open and load the BPF object
  obj = bpf_object__open_file(bpf_object_file, NULL);
  if (!obj) {
    fprintf(stderr, "ERROR: bpf_object__open_file() failed\n");
    return 1;
  }
  err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "ERROR: bpf_object__load() failed\n");
    bpf_object__close(obj);
    return 1;
  }

  // 2) Find the program by its section ("socket")
  prog = bpf_object__find_program_by_title(obj, bpf_prog_section);
  if (!prog) {
    fprintf(stderr, "ERROR: couldn't find section '%s'\n", bpf_prog_section);
    bpf_object__close(obj);
    return 1;
  }
  prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0) {
    fprintf(stderr, "ERROR: bpf_program__fd() failed\n");
    bpf_object__close(obj);
    return 1;
  }

  // 3) Find the existing port_count_map
  map = bpf_object__find_map_by_name(obj, bpf_map_name);
  if (!map) {
    fprintf(stderr, "ERROR: couldn't find map '%s'\n", bpf_map_name);
    bpf_object__close(obj);
    return 1;
  }
  map_fd = bpf_map__fd(map);
  if (map_fd < 0) {
    fprintf(stderr, "ERROR: bpf_map__fd() for port_count_map failed\n");
    bpf_object__close(obj);
    return 1;
  }

  // 4) Find our new http_snippet_map
  snippet_map = bpf_object__find_map_by_name(obj, http_snippet_map_name);
  if (!snippet_map) {
    fprintf(stderr, "ERROR: couldn't find map '%s'\n", http_snippet_map_name);
    bpf_object__close(obj);
    return 1;
  }
  snippet_map_fd = bpf_map__fd(snippet_map);
  if (snippet_map_fd < 0) {
    fprintf(stderr, "ERROR: bpf_map__fd() for http_snippet_map failed\n");
    bpf_object__close(obj);
    return 1;
  }

  // 5) Create a raw packet socket and attach eBPF
  sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_fd < 0) {
    perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)");
    bpf_object__close(obj);
    return 1;
  }

  err =
      setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
  if (err) {
    perror("setsockopt(SO_ATTACH_BPF)");
    close(sock_fd);
    bpf_object__close(obj);
    return 1;
  }

  printf("eBPF socket filter attached. Monitoring:\n");
  printf("  - SSH (22) & HTTPS (443) packet counters\n");
  printf("  - snippet from HTTP (8080) traffic\n\n");

  // 6) Periodically read counters & snippet
  __u16 ports[2] = {22, 443};
  while (1) {
    // (a) Print port counters
    for (int i = 0; i < 2; i++) {
      __u64 value = 0;
      if (bpf_map_lookup_elem(map_fd, &ports[i], &value) == 0) {
        printf("Port %u => %llu packets\n", ports[i], value);
      } else {
        // If not found, zero
        printf("Port %u => 0 packets\n", ports[i]);
      }
    }

    // (b) Check snippet map
    __u32 key = 0;
    struct http_snippet snippet;
    memset(&snippet, 0, sizeof(snippet));
    if (bpf_map_lookup_elem(snippet_map_fd, &key, &snippet) == 0) {
      // If used==1, we have new data
      if (snippet.used == 1) {
        printf("HTTP snippet: '");
        // TODO: Make the lenght dynamic.
        for (int i = 0; i < HTTP_MAX_BYTES; i++) {
          unsigned char c = snippet.data[i];
          // ASCII printable range roughly 32..126
          if (c >= 32 && c <= 126) {
            putchar(c);
          } else {
            putchar('.');
          }
        }
        printf("'\n");

        // reset it to 0 so we don't re-print forever
        snippet.used = 0;
        bpf_map_update_elem(snippet_map_fd, &key, &snippet, BPF_ANY);
      }
    }

    printf("------\n");
    sleep(5);
  }

  // Not reached in this example
  close(sock_fd);
  bpf_object__close(obj);
  return 0;
}
