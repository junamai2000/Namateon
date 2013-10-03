/* vim: set expandtab tabstop=2 shiftwidth=2 softtabstop=2 filetype=c: */
#define MODULE_IDENTITY "namateon"
#define MODULE_CONFIG "conf"
#define MODULE_REV "0.1.0"
#define MAX_CONFIG_LENGTH 8192

typedef struct {
    const char* path;
    const char* proxy_server;
    int proxy_port;
    /* kernel's list structure */
    struct list_head list;
} reverse_proxy;

typedef struct {
    int port;
    ushort syn_backlog;
    const char* ip;
    reverse_proxy proxy_list;
} namateon_server_config;
