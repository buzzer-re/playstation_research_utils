#include "ps4.h"
#include "module.h"

#define KLOG_DEVICE "/dev/klog"
#define SLEEP_TIME_MICRO 1000 // microseconds
#define BUFF_SIZE 0x1000 
#define LISTEN_PORT 9430
#define SYS_fork 2 

typedef unsigned char uchar;

int (*pfork)();

void eternal_read(int fd)
{
    uchar* buff = calloc(BUFF_SIZE, sizeof(uchar));
    
    //struct sock
    // In theory, we should never hit here
    //
    int conn;
    int size;
    int socket = sceNetSocket("klogsocket", AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sock;
    sock.sin_family = AF_INET;
    sock.sin_port = htons(LISTEN_PORT);
    sock.sin_addr.s_addr = IN_ADDR_ANY;

    if (sceNetBind(socket, (struct sockaddr *) &sock, sizeof(sock)) < 0)
    {
        printf_notification("Unable to bind socket! aborting...");
        return;
    }   

    if (sceNetListen(socket, 10))
    {
        printf_notification("Unable to listen! aborting...");
        return;
    }

    printf_notification("Waiting connections...");
    while (1)
    {
        conn = sceNetAccept(socket, NULL, NULL);

        if (conn > 0)
        {
            printf_notification("Connection received sending logs!\n", conn);
            
            while (1)
            {
                size = read(fd, buff, BUFF_SIZE);
                if (size > 0)
                {
                    buff[++size] = 0x00;
                    if (sceNetSend(conn, buff, size, 0) != size)
                    {
                        SckClose(conn);
                        break;
                    }
                }
                sceKernelUsleep(SLEEP_TIME_MICRO);
            }
        }
    }

    SckClose(socket);
    free(buff);
}

int _main()
{
    initKernel();
    initLibc();
    jailbreak();
    initSysUtil();
    initNetwork();
    
    
    //
    // Detach for the loader process
    //
    int pid = getpid();
    syscall(SYS_fork);
    
    if (getpid() == pid)
    {
        goto exit;
    }

    int klog_fd = open(KLOG_DEVICE, O_RDONLY, 0);
    if (klog_fd < 0)
    {
       printf_notification("Unable to open "KLOG_DEVICE"!");
       return 1;
    }

    eternal_read(klog_fd);

    close(klog_fd);

exit:
    return 0;
}
