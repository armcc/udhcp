/* nettel.c -- NETtel specific functions for the DHCP server */
#ifdef CONFIG_NETtel

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#include "dhcpd.h"


int commitChanges() {
        char value[5];
        pid_t pid;
        FILE *in;

        /* get the pid of flatfsd */
        if ((in = fopen("/var/log/flatfsd.pid", "r")) == NULL)
                return -1;

        if(fread(&pid, sizeof(pid_t), 1, in) <= 0) {
                fclose(in);
                return -1;
        }
        fclose(in);

        if((kill(pid, 10)) == -1)
                return -1;
        return 0;
}


int route_add_host(int type) {
        pid_t pid;
        char *argv[16];
        int s, argc = 0;

        /* route add -host 255.255.255.255 eth0 */
        if((pid = vfork()) == 0) { /* child */
                argv[argc++] = "/bin/route";
                if(type == ADD)
                        argv[argc++] = "add";
                else if(type == DEL)
                        argv[argc++] = "del";
                argv[argc++] = "-host";
                argv[argc++] = "255.255.255.255";
                argv[argc++] = "eth0";
                argv[argc] = NULL;
                execvp("/bin/route", argv);
                exit(0);
        } else if (pid > 0) {
                waitpid(pid, &s, 0);
	}
        return 0;
}

#endif
