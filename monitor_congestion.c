#include "monitor_congestion.h"

static int msg_len, msg_len_temp, update_iterator;

char msg[MAX_SOCKETS_CONGS * MAX_MONITOR_LINE_SIZE] ,line_msg[MAX_MONITOR_LINE_SIZE];

static struct nf_hook_ops nfho;


static struct socket_conges conges_array[MAX_SOCKETS_CONGS + 5 ];
static int conges_size , conges_iter;

static void __update_msg(void){
    int i;
    // pr_debug("monitor_congestion: update message");
    msg_len = 0;
    strcpy(msg,"");
    for(i = 0; i < conges_size; ++i){
        msg_len += sprintf(line_msg , "monitor_congestion: %pI4h:%d -> %pI4h:%d ca_states: %d %d %d %d %d   %d\n", &conges_array[i].saddr, conges_array[i].sport,
            &conges_array[i].daddr, conges_array[i].dport, conges_array[i].ca_state_arr[0], conges_array[i].ca_state_arr[1], conges_array[i].ca_state_arr[2],
            conges_array[i].ca_state_arr[3], conges_array[i].ca_state_arr[4], conges_array[i].transfer_size) ;
        strcat(msg,line_msg);
    }
    msg_len_temp = msg_len;
}

/* Update output every ($UPDATE_PERIOD) packet*/
static void update_msg(void){
    update_iterator = (update_iterator + 1) %UPDATE_PERIOD;
    if(!update_iterator){
        __update_msg();
    }
}


int read_proc(struct file *filp,char *buf,size_t count,loff_t *offp ) {
    if(count>msg_len_temp){
        count = msg_len_temp;
    }
    msg_len_temp = msg_len_temp - count;

    // pr_debug("monitor_congestion: user read count = %d,  total size  =%d, iter = %d\n", count, conges_size, conges_iter);
    copy_to_user(buf,msg, count);
    if(count==0)
        msg_len_temp = msg_len;

    // pr_debug("monitor_congestion: msg is");
    // pr_debug(msg);

    return count;
}

int write_proc(struct file *filp,const char *buf,size_t count,loff_t *offp){
    copy_from_user(msg,buf,count);
    msg_len = count;
    msg_len_temp = msg_len;
    pr_debug("monitor_congestion: user write this : %s\n", msg);
    return count;
}

struct file_operations proc_fops = {
    .read = read_proc,
    .write = write_proc
};

void create_new_proc_entry(void) {
    proc_create(PROCNAME, S_IRUGO | S_IWUGO | S_IXUGO,NULL,&proc_fops);
    // msg=kmalloc(GFP_KERNEL,100*sizeof(char));
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
    u64 packet_size;                 /* Packet size */
    int i = 0;
    u16 ca_state = 0;   
    struct inet_connection_sock *icsk ;
    // char *s_temp;

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

    /* Get packet size */
    packet_size = skb->len;  /* TODO asure total size (paged + linear) */

    /* Get congestion state */
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

        ca_state = icsk->icsk_ca_state;

        if(ca_state > 4){
            pr_debug("monitor_congestion: Strange number for state  %d\n",ca_state);
            return NF_ACCEPT;
        }

        if(ca_state != 0){
            /* Print packet route */
            pr_debug("monitor_congestion: Non zero state: %pI4h:%d -> %pI4h:%d  state is %d\n", &saddr, sport,&daddr, dport, ca_state);
        }

        // TODO just initate the struct object if not match 
        struct socket_conges current_cs =  {
            .saddr = saddr,
            .daddr = daddr,
            .sport = sport,
            .dport = dport,
            .ca_state = ca_state,
            .ca_state_arr = {0,0,0,0,0},
            .transfer_size = packet_size,
            .sk = sk
        };

        bool scg_found = false;
        for(; i < conges_size; ++i){
            if(socket_conges_match(&current_cs, &conges_array[i])){
                // pr_debug("monitor_congestion: match\n");
                // pr_debug("monitor_congestion: match : %pI4h:%d -> %pI4h:%d  with: %pI4h:%d -> %pI4h:%d\n", &current_cs.saddr, current_cs.sport, &conges_array[i].saddr, conges_array[i].sport , &current_cs.daddr, current_cs.dport , &conges_array[i].daddr, conges_array[i].dport);

                // Save last state value 
                conges_array[i].ca_state = ca_state;

                // Increase the counter for this state
                conges_array[i].ca_state_arr[ca_state]++;

                /* Increase packet size */
                conges_array[i].transfer_size += packet_size;

                scg_found = true;
                break;
            }
        }
        if(!scg_found){
            /* add new session */
            // pr_debug("monitor_congestion: new socket cong iter = %d, cong size = %d\n", conges_iter, conges_size);
            current_cs.ca_state_arr[ca_state]++;
            conges_array[conges_iter] = current_cs;
            conges_iter = (conges_iter + 1 ) % MAX_SOCKETS_CONGS;
            conges_size = min(conges_size +1 , MAX_SOCKETS_CONGS);
        }

        /* update it's output */
        update_msg();

    }
    else{
        // sk not found
        pr_debug("monitor_congestion: sk not found: %pI4h:%d -> %pI4h:%d\n", &saddr, sport,&daddr, dport);
    }

    return NF_ACCEPT;
}

static int __init ptcp_init(void)
{
    int res;

    nfho.hook = (nf_hookfn *)ptcp_hook_func;    /* hook function */

    /* send packets */
    nfho.hooknum = NF_INET_POST_ROUTING;
    /* received packets */
    // nfho.hooknum = NF_INET_LOCAL_IN;
    
    nfho.pf = PF_INET;                          /* IPv4 */
    nfho.priority = NF_IP_PRI_FIRST;            /* max hook priority */

    res = nf_register_hook(&nfho);
    if (res < 0) {
        pr_err("monitor_congestion: error in nf_register_hook()\n");
        return res;
    }

    conges_iter = 0;
    conges_size = 0;
    update_iterator = 0;

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

