/* vim: set expandtab tabstop=2 shiftwidth=2 softtabstop=2 filetype=c: */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/types.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <net/sock.h>

#include "namateon.h"
#include "nxjson.h"
#include "http_server.h"
#include "http_parser.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Namateon Application Switch");
MODULE_AUTHOR("Junya Namai");

#define MODULE_IDENTITY "namateon"
#define MAX_CONFIG_LENGTH 8192
static struct proc_dir_entry *dir_entry;
#define MODULE_CONFIG "conf"
static struct proc_dir_entry *conf_entry;
#define MODULE_SERVER_START "start"
static struct proc_dir_entry *start_entry;
static int is_started=0;
static char *server_config_raw;
namateon_server_config* server_config;
struct socket *listen_socket;
struct http_server_param param;
struct task_struct *http_server;

static int open_listen_socket (struct socket **res)
{
	struct socket *sock;
	int err, opt = 1;
	struct sockaddr_in s;

	err = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err < 0)
    {
		printk(KERN_ERR MODULE_IDENTITY ": sock_create_kern() failure, err=%d\n", err);
		return err;
	}
	opt = 1;
	err = kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
	if (err < 0)
    {
		printk(KERN_ERR MODULE_IDENTITY": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	opt = 1;
	err = kernel_setsockopt(sock, SOL_TCP, TCP_NODELAY, (char *)&opt, sizeof(opt));
	if (err < 0)
    {
		printk(KERN_ERR MODULE_IDENTITY": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	opt = 0;
	err = kernel_setsockopt(sock, SOL_TCP, TCP_CORK, (char *)&opt, sizeof(opt));
	if (err < 0)
    {
		printk(KERN_ERR MODULE_IDENTITY": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	opt = 1024 * 1024;
	err = kernel_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&opt, sizeof(opt));
	if (err < 0)
    {
		printk(KERN_ERR MODULE_IDENTITY": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	opt = 1024 * 1024;
	err = kernel_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&opt, sizeof(opt));
	if (err < 0)
    {
		printk(KERN_ERR MODULE_IDENTITY": kernel_setsockopt() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = htonl(INADDR_ANY);
	s.sin_port = htons(server_config->port);
	err = kernel_bind(sock, (struct sockaddr *)&s, sizeof(s));
	if (err < 0)
    {
		printk(KERN_ERR MODULE_IDENTITY": kernel_bind() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
	err = kernel_listen(sock, server_config->syn_backlog);
	if (err < 0)
    {
		printk(KERN_ERR MODULE_IDENTITY": kernel_listen() failure, err=%d\n", err);
		sock_release(sock);
		return err;
	}
		printk(KERN_ERR MODULE_IDENTITY": namateon started\n");
	*res = sock;
	return 0;
}

namateon_server_config* namateon_config_parse(char* input)
{
    namateon_server_config* sc;
    const nx_json* json;
    int i;
    sc = (namateon_server_config*)kmalloc(sizeof(server_config), GFP_KERNEL);
    printk(KERN_INFO MODULE_IDENTITY ": %s\n", input);
    json = nx_json_parse_utf8(input);
    if (json)
    {
          printk(KERN_INFO MODULE_IDENTITY ": server=%s\n", nx_json_get(json, "server")->text_value);
          printk(KERN_INFO MODULE_IDENTITY ": port=%ld\n", nx_json_get(json, "port")->int_value);
          printk(KERN_INFO MODULE_IDENTITY ": ip=%s\n", nx_json_get(json, "ip")->text_value);
          sc->port = nx_json_get(json, "port")->int_value;
          sc->ip = nx_json_get(json, "ip")->text_value;
          sc->syn_backlog = nx_json_get(json, "backlog")->int_value;

          INIT_LIST_HEAD(&sc->proxy_list.list);
          const nx_json* arr=nx_json_get(json, "location");
          for (i=0; i<arr->length; i++) {
              const nx_json* item = nx_json_item(arr, i);
              reverse_proxy* proxy;
              proxy = kmalloc(sizeof(reverse_proxy), GFP_KERNEL);
              proxy->path = nx_json_get(item, "path")->text_value;
              proxy->proxy_server = nx_json_get(item, "proxy_server")->text_value;
              proxy->proxy_port = nx_json_get(item, "proxy_port")->int_value;
              list_add_tail(&proxy->list, &sc->proxy_list.list);
          
              printk(KERN_INFO MODULE_IDENTITY ": path=%s server:%s, port:%d\n", proxy->path, proxy->proxy_server, proxy->proxy_port);
          }
    }
    return sc;
}

static void
close_listen_socket (struct socket *socket) {
	kernel_sock_shutdown(socket, SHUT_RDWR);
	sock_release(socket);
}

/*
 *
 * Server configuration /proc entry
 */
int server_config_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len;
    if (off > 0)
    {
        *eof = 1;
        return 0;
    }
    len = sprintf(page, "%s\n", server_config_raw);
    return len;
}

ssize_t server_config_write(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
    if (len > MAX_CONFIG_LENGTH)
    {
        printk(KERN_INFO MODULE_IDENTITY ": conf file is too long\n");
        return -ENOSPC;
    }
    if (copy_from_user(server_config_raw, buff, len))
    {
        return -EFAULT;
    }

    server_config = namateon_config_parse(server_config_raw); 
    return len;
}

/*
 *
 * Server deamon /proc entry
 */
int server_start_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
    int len;
    if (off > 0)
    {
        *eof = 1;
        return 0;
    }
    len = sprintf(page, "%d\n", is_started);
    return len;
}
ssize_t server_start_write(struct file *filp, const char __user *buff, unsigned long len, void *data)
{
    int err;
    char *start = (char *)kmalloc(10, GFP_KERNEL);;
    if (len > 2)
    {
        printk(KERN_INFO MODULE_IDENTITY ": must be 1 or 0. input length is %ld\n", len);
        return -ENOSPC;
    }
    if (copy_from_user(start, buff, len))
    {
        printk(KERN_INFO MODULE_IDENTITY ": failed to copy from user\n");
        return -EFAULT;
    }
    
    if (*start=='1')	
    {
        err = open_listen_socket(&listen_socket);
        if (err < 0) {
            printk(KERN_ERR MODULE_IDENTITY ": can't open listen socket\n");
            return err;
        } 

        param.listen_socket = listen_socket;
        http_server = kthread_run(http_server_daemon, &param, MODULE_IDENTITY);
        if (IS_ERR(http_server)) {
            printk(KERN_ERR MODULE_IDENTITY ": can't start http server daemon\n");
            close_listen_socket(listen_socket);
        }
        printk(KERN_ERR MODULE_IDENTITY ": http server daemon started\n");
        is_started=1;
    }
    else
    {
        send_sig(SIGTERM, http_server, 1);
        kthread_stop(http_server);
        close_listen_socket(listen_socket);
        printk(KERN_ERR MODULE_IDENTITY ": http server daemon stopped\n");
        is_started=0;
    }
    kfree(start);

    return len;
}

int init_namateon_module(void)
{
    int ret = 0;
    server_config_raw = (char *)kmalloc(MAX_CONFIG_LENGTH, GFP_KERNEL);

    if (!server_config_raw)
    {
        ret = -ENOMEM;
    }
    else
    {
        memset(server_config_raw, 0, MAX_CONFIG_LENGTH);
        dir_entry = proc_mkdir(MODULE_IDENTITY, NULL);
        if (dir_entry == NULL)
        {
            ret = -ENOMEM;
            kfree(server_config_raw);
            printk(KERN_INFO MODULE_IDENTITY ": Couldn't create proc dir\n");
        }
        conf_entry = create_proc_entry(MODULE_CONFIG, 0644, dir_entry);
        if (conf_entry == NULL)
        {
            ret = -ENOMEM;
            kfree(server_config_raw);
            printk(KERN_INFO MODULE_IDENTITY ": Couldn't create proc entry\n");
        }
        else
        {
            conf_entry->read_proc = server_config_read;
            conf_entry->write_proc = server_config_write;
            printk(KERN_INFO MODULE_IDENTITY ": Module loaded.\n");
        }
        
        start_entry = create_proc_entry(MODULE_SERVER_START, 0644, dir_entry);
        if (start_entry == NULL)
        {
            ret = -ENOMEM;
            kfree(server_config_raw);
            printk(KERN_INFO MODULE_IDENTITY ": Couldn't create start entry\n");
        }
        else
        {
            start_entry->read_proc = server_start_read;
            start_entry->write_proc = server_start_write;
        }
    }
    return ret;
}


void cleanup_namateon_module( void )
{
    remove_proc_entry(MODULE_IDENTITY, NULL);
    kfree(server_config_raw);
    if (is_started==1)
    {
        send_sig(SIGTERM, http_server, 1);
        kthread_stop(http_server);
        close_listen_socket(listen_socket);
    }
    printk(KERN_INFO MODULE_IDENTITY ": Module unloaded.\n");
}

module_init(init_namateon_module);
module_exit(cleanup_namateon_module);
