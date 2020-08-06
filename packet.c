#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/time.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fateme");
MODULE_DESCRIPTION("A simple module for packet drop.");
MODULE_VERSION("0.1");
#define  DEVICE_NAME "packet4"
#define  CLASS_NAME  "droper4"
#define  MAX 25
#define  MAXNUM 10

static int     dev_openn(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct class*  PClass  = NULL;
static struct device* PDevice = NULL;

struct sk_buff *sock_buff, *sock_buff2;
struct iphdr *ip_header;
struct tcphdr *tcp_header;
struct udphdr *udp_header;

static int majorNumber;

int ip_count = 0;
char ip_port[MAXNUM][MAX];

static struct file_operations fops =
{
   .open = dev_openn,
   .write = dev_write,
   .release = dev_release,
};

int mode = 1; // 0 : whitelist , 1:blacklist

unsigned int packet_hook(unsigned int hooknum, struct sk_buff *skb,
                       const struct net_device *in, const struct net_device *out,
                       int(*okfn)(struct sk_buff *));


static struct nf_hook_ops packet_drop __read_mostly = {
    .pf = NFPROTO_IPV4,
    .priority = NF_IP_PRI_FIRST,
    .hooknum =NF_INET_LOCAL_IN,
    .hook = (nf_hookfn *) packet_hook
};

static int __init packet_drop_init(void)
{
    int ret = 0;
    printk(KERN_INFO "inteligent packet droper loaded!:)\n");

    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber<0)
    {
        printk(KERN_ALERT "PDroper failed to register a major number\n");
        return majorNumber;
    }
    printk(KERN_INFO "PDroper: registered correctly with major number %d\n", majorNumber);

    PClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(PClass))
    {
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(PClass);
    }
    printk(KERN_INFO "PDroper: device class registered correctly\n");

    PDevice = device_create(PClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(PDevice)){
        class_destroy(PClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(PDevice);
    }

    ret = nf_register_net_hook(&init_net,&packet_drop);
    if(ret)
        printk(KERN_INFO "FAILED");

    return  ret;

}

static void __exit  packet_drop_exit(void)
{
    device_destroy(PClass, MKDEV(majorNumber, 0));     // remove the device
    class_unregister(PClass);                          // unregister the device class
    class_destroy(PClass);                            // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_INFO "inteligent packet droper module unloaded, BYE!\n");
    nf_unregister_net_hook(&init_net,&packet_drop); /*UnRecord in net filtering */
}


static ssize_t dev_write(struct file *filep, const char *buf, size_t count, loff_t *position)
{

    char message[MAX];
    int i;
    printk(KERN_INFO "PDroper: Received %zu characters from the user\n", count);
    if (count > MAX)
        return -EINVAL;

    if (copy_from_user(message, buf, MAX) != 0)
        return -EFAULT;
    sscanf(message,"%d",&i);
    if(i == 0)
    {
        sscanf(message,"%d %d",&i, &mode);
        printk(KERN_INFO "mode understood mode: %d", mode);
    }
    else
    {
        strcpy(ip_port[ip_count++], message);
        printk(KERN_INFO "ip and port added to list : %s", ip_port[ip_count-1]);
    }
    return count;
}
static int dev_release(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "Pdroper: Device successfully closed\n");
    return 0;
}
static int dev_openn(struct inode *inodep, struct file *filep){
   //numberOpens++;
   printk(KERN_INFO "Pdroper: Device has been opened.\n");
   return 0;
}


unsigned int packet_hook(unsigned int hooknum, struct sk_buff *skb,
        const struct net_device *in, const struct net_device *out,
        int(*okfn)(struct sk_buff *))
{
    struct timespec time;
    char source[16], tmp[50];
    int flag = 0, i, flag1=0;
    int sport, dport;

    sock_buff = skb;
    sock_buff2 = skb;
    if(!sock_buff) { return NF_DROP;}

    ip_header = (struct iphdr *)skb_network_header(sock_buff);
    snprintf(source, 16, "%pI4", &ip_header->saddr);

    if(ip_header->protocol==IPPROTO_TCP)
    {
        tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl); //this fixed the problem

        sport = htons((unsigned short int) tcp_header->source); //sport now has the source port
        dport = htons((unsigned short int) tcp_header->dest);   //dport now has the dest port
        sprintf(tmp, "%s:%d\n", source, sport);
        printk(KERN_INFO "TCP packet recieved from %s", tmp);
        for (i = 0; i < ip_count; i++) {
            if(!strcmp(tmp, ip_port[i]))
            {
                flag = 1;
                break;
            }
        }
        if(mode == 0 && flag == 0)
        {
            getnstimeofday(&time);
            printk(KERN_INFO "packet isnt in whitelist, packet dropped, time:%ld", time.tv_sec);
            return NF_DROP;
        }
        if(mode == 1 && flag == 1)
        {
            getnstimeofday(&time);
            printk(KERN_INFO "packet is in blacklist, packet dropped, time:%ld", time.tv_sec);
            return NF_DROP;
        }
        printk(KERN_INFO "packet didnt drop");
        return NF_ACCEPT;
    }

    /*if(ip_header->protocol==IPPROTO_UDP)
    {
        udp_header= (struct udphdr *)((__u32 *)ip_header+ ip_header->ihl); //this fixed the problem

        sport = htons((unsigned short int) udp_header->source); //sport now has the source port
        dport = htons((unsigned short int) udp_header->dest);   //dport now has the dest port
        sprintf(tmp, "%s:%d\n", source, sport);
        printk(KERN_INFO "UDP packet recieved from %s", tmp);
        for (i = 0; i < ip_count; i++) {
            if(!strcmp(tmp, ip_port[i]))
            {
                flag = 1;
                break;
            }
        }
        if(mode == 0 && flag == 0)
        {
            getnstimeofday(&time);
            printk(KERN_INFO "packet isnt in whitelist, packet dropped, time:%ld", time.tv_sec);
            return NF_DROP;
        }
        if(mode == 1 && flag1 == 1)
        {
            getnstimeofday(&time);
            printk(KERN_INFO "packet is in blacklist, packet dropped, time:%ld", time.tv_sec);
            return NF_DROP;
        }
        printk(KERN_INFO "packet didnt drop");
        return NF_ACCEPT;
    }*/

    return NF_ACCEPT;
}

module_init(packet_drop_init);
module_exit(packet_drop_exit);
