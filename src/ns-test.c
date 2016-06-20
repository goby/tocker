#define _GNU_SOURCE_

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/capability.h>
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)
#define HOSTNAME "container"
static char container_stack[STACK_SIZE];
static char container_user_stack[STACK_SIZE];

char* const container_args[] = {
    "/bin/bash",
    NULL
};

int pipefd[2];

void set_map(char* file, int inside_id, int outside_id, int len) {
    FILE* mapfd = fopen(file, "w");
    if (NULL == mapfd) {
        perror("open file error");
        return;
    }
    fprintf(mapfd, "%d %d %d", inside_id, outside_id, len);
    fclose(mapfd);
}
 
void set_uid_map(pid_t pid, int inside_id, int outside_id, int len) {
    char file[256];
    sprintf(file, "/proc/%d/uid_map", pid);
    set_map(file, inside_id, outside_id, len);
}
 
void set_gid_map(pid_t pid, int inside_id, int outside_id, int len) {
    char file[256];
    sprintf(file, "/proc/%d/gid_map", pid);
    set_map(file, inside_id, outside_id, len);
}

int container_main(void *args) {
    printf("[D] Container - inside the container!\n");
    
    if(sethostname(HOSTNAME, sizeof(HOSTNAME)) != 0) {
        perror("[E] set host name failed");
        return 1;
    }

    if (mount("proc", "rootfs/proc", "proc", 0, NULL) !=0 ) {
        perror("[E] mount proc");
    }
    if (mount("sysfs", "rootfs/sys", "sysfs", 0, NULL)!=0) {
        perror("[E] mount sys");
    }
    if (mount("none", "rootfs/tmp", "tmpfs", 0, NULL)!=0) {
        perror("[E] mount tmp");
    }
    if (mount("udev", "rootfs/dev", "devtmpfs", 0, NULL)!=0) {
        perror("[E] mount dev");
    }
    if (mount("devpts", "rootfs/dev/pts", "devpts", 0, NULL)!=0) {
        perror("[E] mount dev/pts");
    }
    if (mount("shm", "rootfs/dev/shm", "tmpfs", 0, NULL)!=0) {
        perror("[E] mount dev/shm");
    }
    if (mount("tmpfs", "rootfs/run", "tmpfs", 0, NULL)!=0) {
        perror("[E] mount run");
    }

    if (mount("conf/hosts", "rootfs/etc/hosts", "none", MS_BIND, NULL)!=0 ||
          mount("conf/hostname", "rootfs/etc/hostname", "none", MS_BIND, NULL)!=0 ||
          mount("conf/resolv.conf", "rootfs/etc/resolv.conf", "none", MS_BIND, NULL)!=0 ) {
        perror("[E] mount conf");
    }
    /* 模仿docker run命令中的 -v, --volume=[] 参数干的事 */
    if (mount("/tmp/t1", "rootfs/mnt", "none", MS_BIND, NULL)!=0) {
        perror("[E] mount mnt");
    }
 
    /* chroot 隔离目录 */
    if ( chdir("./rootfs") != 0 || chroot("./") != 0 ){
        perror("[E] chdir/chroot");
    }

    execv(container_args[0], container_args);

    perror("[E] something' wrong!\n");

    return 1;
}

int container_user(void *args) {

    printf("[D] Child - waiting parent preparing env\n");

    char ch;
    close(pipefd[1]);
    read(pipefd[0], &ch, 1);

    printf("[D] Child [%5d] - start the main container!\n", getpid());

    int container_pid = clone(container_main, container_stack + STACK_SIZE,
                              SIGCHLD | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNS,
                              NULL);
    if (container_pid < 0) {
        perror("[E] clone failed");
        return 1;
    }

    waitpid(container_pid, NULL, 0);

    return 0;
}

int main(int argc, char * argv[]) {

    const int gid = getgid(), uid = getuid();

    printf("[D] Parent[%5d] - start a container!\n", getpid());

    pipe(pipefd);
    
    int user_pid = clone(container_user, container_user_stack + STACK_SIZE,
                              SIGCHLD | CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWUTS,
                              NULL);

    if (user_pid < 0) {
        perror("[E] Parent clone failed");
        return 1;
    }

    printf("[D] Parent - preparing env\n");

    set_uid_map(user_pid, 0, uid, 1);
    set_gid_map(user_pid, 0, gid, 1);

    printf("[D] Parent - setuped env\n");

    close(pipefd[1]);

    waitpid(user_pid, NULL, 0);
    printf("[D] Parent - container stopped!\n");

    return 0;
} 
