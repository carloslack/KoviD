// This file is a user-space loader that attaches the socket_filter_prog eBPF
// program to a raw socket (AF_PACKET, SOCK_RAW). It then periodically reads
// and prints packet counters for SSH (port 22) and HTTPS (port 443) traffic.

// clang -o socket_filter_user main.c \
//    -I/usr/include \
//    -L/usr/lib64 -lbpf -lelf -lz

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * This user-space program:
 *  1) Loads the compiled socket_filter_bpf.o.
 *  2) Attaches the eBPF program to a raw packet socket.
 *  3) Periodically prints packet counters for ports 22 & 443.
 */

static const char *bpf_object_file = "./socket_filter_bpf.o";
static const char *bpf_program_name = "socket_filter_prog";
static const char *bpf_map_name = "port_count_map";

int main(int argc, char **argv) {
  struct bpf_object *obj = NULL;
  struct bpf_program *prog = NULL;
  struct bpf_map *map = NULL;
  int prog_fd, map_fd;
  int sock_fd;
  int err;

  // Open the BPF object file
  obj = bpf_object__open_file(bpf_object_file, NULL);
  if (!obj) {
    fprintf(stderr, "ERROR: bpf_object__open_file() failed\n");
    return 1;
  }

  // Load (verify) the BPF program
  err = bpf_object__load(obj);
  if (err) {
    fprintf(stderr, "ERROR: bpf_object__load() failed\n");
    bpf_object__close(obj);
    return 1;
  }

  // Find the program by its section name
  prog = bpf_object__find_program_by_title(obj, "socket");
  if (!prog) {
    fprintf(stderr, "ERROR: couldn't find 'socket' program\n");
    bpf_object__close(obj);
    return 1;
  }

  prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0) {
    fprintf(stderr, "ERROR: bpf_program__fd() failed\n");
    bpf_object__close(obj);
    return 1;
  }

  // Find the map (port_count_map)
  map = bpf_object__find_map_by_name(obj, bpf_map_name);
  if (!map) {
    fprintf(stderr, "ERROR: couldn't find map '%s'\n", bpf_map_name);
    bpf_object__close(obj);
    return 1;
  }

  map_fd = bpf_map__fd(map);
  if (map_fd < 0) {
    fprintf(stderr, "ERROR: bpf_map__fd() failed\n");
    bpf_object__close(obj);
    return 1;
  }

  // Create a raw packet socket (AF_PACKET), see all traffic (ETH_P_ALL)
  sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_fd < 0) {
    perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)");
    bpf_object__close(obj);
    return 1;
  }

  // Attach the eBPF program to this socket
  err =
      setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
  if (err) {
    perror("setsockopt(SO_ATTACH_BPF)");
    close(sock_fd);
    bpf_object__close(obj);
    return 1;
  }

  printf("eBPF socket filter attached. Monitoring SSH (22) & HTTPS (443)...\n");

  // Periodically read the counters for ports 22 and 443
  __u16 ports[2] = {22, 443};
  while (1) {
    for (int i = 0; i < 2; i++) {
      __u64 value = 0;
      if (bpf_map_lookup_elem(map_fd, &ports[i], &value) == 0) {
        printf("Port %u => %llu packets\n", ports[i], value);
      } else {
        // If not found, it's not in the map yet => zero packets
        printf("Port %u => 0 packets\n", ports[i]);
      }
    }
    printf("------\n");
    sleep(5);
  }

  // Cleanup (never actually reached in this snippet)
  close(sock_fd);
  bpf_object__close(obj);
  return 0;
}
