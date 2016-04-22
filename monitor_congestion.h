#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>  /* Necessary because we use proc fs */
#include <linux/seq_file.h> /* for seq_file */
#include <asm/uaccess.h>    /* for copy_*_user */
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>

// #define PTCP_WATCH_PORT     80  /* HTTP port */
#define PROCNAME "monitor_congestion"
#define MAX_SOCKETS_CONGS 1000
#define MAX_MONITOR_LINE_SIZE 120
#define UPDATE_PERIOD 10

/* Struct saving the congestion state of tcp session*/
struct socket_conges{
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */
    u16 ca_state;
    u16 ca_state_arr[5];
    const struct sock *sk;
};

static bool socket_conges_match(struct socket_conges *sc1, struct socket_conges *sc2){
    if(sc1->sk == sc2->sk)
        return true;
    return false;
}

