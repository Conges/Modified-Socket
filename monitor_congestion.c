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
static int len,temp;

static char *msg ,*ana;

#define PROCNAME "monitor_congestion"


static int read_proc(struct file *filp,char *buf,size_t count,loff_t *offp ) {
    if(count>temp){
        count=temp;
    }
    temp=temp-count;
    copy_to_user(buf,msg, count);
    if(count==0)
        temp=len;

    pr_debug("monitor_congestion: user read this : %s", msg);

    return count;
}

static int write_proc(struct file *filp,const char *buf,size_t count,loff_t *offp){
    copy_from_user(msg,buf,count);
    len=count;
    temp=len;
    pr_debug("monitor_congestion: user write this : %s", msg);
    return count;
}

struct file_operations proc_fops = {
    .read = read_proc,
    .write = write_proc
};

void create_new_proc_entry(void) {
    proc_create(PROCNAME, S_IRUGO | S_IWUGO | S_IXUGO,NULL,&proc_fops);
    msg=kmalloc(GFP_KERNEL,10*sizeof(char));
}

static struct nf_hook_ops nfho;
struct socket_conges{
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */        
    u16 ca_state;
    u16 ca_state_repete_count;
    const struct sock *sk;
};

#define MAX_SOCKETS_CONGS 100

static struct socket_conges conges_array[MAX_SOCKETS_CONGS+1];
static int conges_size;

static bool socket_conges_match(struct socket_conges *sc1, struct socket_conges *sc2){
    // if(sc1->sport == sc2->dport && sc1->dport == sc2-> dport &&
    //  sc1->saddr == sc2->saddr && sc1->daddr == sc2->daddr)
    if(sc1->sk == sc2->sk)
        return true;
    return false;
}

static unsigned int ptcp_hook_func(const struct nf_hook_ops *ops,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;          /* IPv4 header */
    struct tcphdr *tcph;        /* TCP header */
    u16 sport, dport;           /* Source and destination ports */
    u32 saddr, daddr;           /* Source and destination addresses */
    int i = 0;
    int ca_state = 0;   
    struct inet_connection_sock *icsk ;
    char *s_temp;

    /* Network packet is empty, seems like some problem occurred. Skip it */
    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);          /* get IP header */

    /* Skip if it's not TCP packet */
    if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);        /* get TCP header */

    /* Convert network endianness to host endiannes */
    saddr = ntohl(iph->saddr);
    daddr = ntohl(iph->daddr);
    sport = ntohs(tcph->source);
    dport = ntohs(tcph->dest);

    /*
        get congestion state
    */
    if(skb->sk){
        // we found the socket
        // pr_debug("found\n");
        struct sock *sk ;
        sk = skb->sk;
        icsk = inet_csk(sk);
        if(!icsk){
            pr_debug("monitor_congestion: icsk not found\n");
            return NF_ACCEPT;
        }

        if(icsk->icsk_ca_state != 0){
            /* Print packet route */
            pr_debug("monitor_congestion: %pI4h:%d -> %pI4h:%d\n", &saddr, sport,&daddr, dport);
            pr_debug("monitor_congestion: state = %d\n",(int)icsk->icsk_ca_state);
        }

        ca_state = icsk->icsk_ca_state;
        struct socket_conges current_cs =  {
            .saddr = saddr,
            .daddr = daddr,
            .sport = sport,
            .dport = dport,
            .ca_state = ca_state,
            .sk = sk
        };

        bool scg_found = false;
        for(; i <= conges_size; ++i){
            if(socket_conges_match(&current_cs, &conges_array[i])){
                pr_debug("monitor_congestion: match");
                conges_array[i].ca_state = current_cs.ca_state;
                scg_found = true;
                break;
            }
        }
        if(!scg_found){
            conges_array[conges_size] = current_cs; 
            conges_size = min(conges_size + 1 , MAX_SOCKETS_CONGS);
            pr_debug("monitor_congestion: new array size is %d", conges_size);
        }
        
        pr_debug("monitor_congestion: states is: ");
        strcpy(msg,"");
        for(i = 0; i < conges_size; ++i){
            // strcpy(s_temp , sprintf("monitor_congestion: %pI4h:%d -> %pI4h:%d ca_state: %d\n", &conges_array[i].saddr, conges_array[i].sport,&conges_array[i].daddr, conges_array[i].dport, conges_array[i].ca_state) );
            // char *s_temp = sprintf("monitor_congestion: %pI4h:%d -> %pI4h:%d ca_state: %d\n", &conges_array[i].saddr, conges_array[i].sport,&conges_array[i].daddr, conges_array[i].dport, conges_array[i].ca_state);
        //     // pr_debug("monitor_congestion: %pI4h:%d -> %pI4h:%d ca_state: %d\n", &conges_array[i].saddr, conges_array[i].sport,&conges_array[i].daddr, conges_array[i].dport, conges_array[i].ca_state);
        }
        pr_debug("\n");

    }
    else{
        // pr_debug("monitor_congestion: %pI4h:%d -> %pI4h:%d\n", &saddr, sport,&daddr, dport);
        // pr_debug("monitor_congestion: not found\n");
    }

    return NF_ACCEPT;
}

static int __init ptcp_init(void)
{
    int res;

    nfho.hook = (nf_hookfn *)ptcp_hook_func;    /* hook function */

    /* send packets */
    nfho.hooknum = NF_INET_LOCAL_IN;
    /* received packets */
    // nfho.hooknum = NF_INET_LOCAL_IN;
    
    nfho.pf = PF_INET;                          /* IPv4 */
    nfho.priority = NF_IP_PRI_FIRST;            /* max hook priority */

    res = nf_register_hook(&nfho);
    if (res < 0) {
        pr_err("monitor_congestion: error in nf_register_hook()\n");
        return res;
    }

    conges_size = 0;
    create_new_proc_entry();

    pr_debug("monitor_congestion:: loaded\n");
    return 0;
}

static void __exit ptcp_exit(void)
{
    nf_unregister_hook(&nfho);
    remove_proc_entry(PROCNAME,NULL);
    pr_debug("monitor_congestion: unloaded\n");
}

module_init(ptcp_init);
module_exit(ptcp_exit);

MODULE_AUTHOR("Ahmed Kamal");
MODULE_DESCRIPTION("Module for Monitor TCP Congestion State");
MODULE_LICENSE("GPL");

