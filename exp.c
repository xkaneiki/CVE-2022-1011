
#define _GNU_SOURCE
#include <sched.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <linux/types.h>
#include <sys/mman.h>
#include "exp.h"

#define DEVNAME "/dev/fuse"
#define FSTYPE "fuse"

#define MNT "./tmp"
void fatal(const char *msg)
{
    perror(msg);
    exit(1);
}
static void xwritefile(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY);
    if (fd == -1)
        err(1, "open %s", path);
    ssize_t len = (ssize_t)strlen(data);
    if (write(fd, data, len) != len)
        err(1, "write %s", path);
    close(fd);
}
void create_ns()
{
    // 创建新的命名空间
    char buf[0x1000];
    uid_t uid, gid;
    uid = getuid();
    gid = getgid();
    if (unshare(CLONE_NEWNS | CLONE_NEWUSER) == -1)
        fatal("unshare");

    xwritefile("/proc/self/setgroups", "deny");
    sprintf(buf, "1000 %d 1", uid);
    xwritefile("/proc/self/uid_map", buf);
    sprintf(buf, "1000 %d 1", gid);
    xwritefile("/proc/self/gid_map", buf);
}

void mount_pfuse(int fd)
{
    // 挂载fuse文件系统
    mkdir(MNT, 0777);
    char opts[0x1000];
    struct stat stbuf;
    int res = lstat(MNT, &stbuf);
    if (res < 0)
        fatal("lstat");
    mode_t rootmode = stbuf.st_mode & S_IFMT;
    sprintf(opts, "fd=%d,rootmode=%o,user_id=%u,group_id=%u", fd, rootmode, getuid(), getgid());
    // system("id");
    puts(opts);
    int ret = mount(DEVNAME, MNT, FSTYPE, MS_NOSUID | MS_NODEV, opts);
    if (ret < 0)
    {
        fatal("mount");
    }
    puts("[+] mount success!");
    system("mount"); // 查看已经挂载的文件系统
}

void clear(int fd)
{
    int ret = umount(MNT);
    if (ret < 0)
        fatal("umount");
    puts("umount success");
    close(fd);
}

int fuse_dev_open(char *path)
{
    int fd = open(path, O_RDWR);
    if (fd < 0)
        fatal("open");
    return fd;
}

void fuse_dev_read(int fd, char *buf, int len)
{
    int ret = 0;
    ret = read(fd, buf, len);
    if (ret < 0)
        fatal("read");
}

void fuse_dev_write(int fd, char *buf, int len)
{
    int ret = 0;
    ret = write(fd, buf, len);
    if (ret < 0)
        fatal("write");
}

void fuse_show_req_head(struct fuse_in_header *in)
{
    fflush(stdout); // 刷新标准输出输出
    puts("-----------------------");
    puts("[+] head in");
    printf("[+] len:\t%d\n", in->len);
    printf("[+] opcode:\t%s[%d]\n", fuse_ll_ops[in->opcode], in->opcode);
    printf("[+] unique:\t%d\n", in->unique);
    printf("[+] nodeid:\t%d\n", in->nodeid);
    printf("[+] uid:\t%d\n", in->uid);
    printf("[+] gid:\t%d\n", in->gid);
    printf("[+] padding:\t%d\n", in->padding);
    puts("-----------------------");
}

char *fuse_receive_req(int fd)
{
    puts("[+] start recv");
    size_t bufsize = getpagesize() + 0x1000;
    char *buf = malloc(bufsize);
    fuse_dev_read(fd, buf, bufsize);
    struct fuse_in_header *in = (struct fuse_in_header *)buf;
    fuse_show_req_head(in);
    puts("[+] end recv");
    return buf;
}

void fuse_send_reply(int fd, void *arg, size_t argsize, int error, size_t unique)
{
    struct iovec iov[2];
    int count = 1;
    // 第一个iov存储out头
    struct fuse_out_header out;
    iov[0].iov_base = &out;
    iov[0].iov_len = sizeof(struct fuse_out_header);
    out.unique = unique;
    out.error = error;

    // 第二个iov存储参数信息
    if (argsize)
    {
        iov[1].iov_base = (void *)arg;
        iov[1].iov_len = argsize;
        count++;
    }
    out.len = iov_length(iov, count);

    printf("unique: %llu, success, outsize: %i\n",
           (unsigned long long)out.unique, out.len);
    int res = writev(fd, iov, count);
    printf("fd: %d\n", fd);
    if (res < 0)
        fatal("fuse send reply");
}

void fuse_show_init_in(struct fuse_init_in *in)
{
    fflush(stdout); // 刷新标准输出输出
    puts("-----------------------");
    puts("[+] init in");
    printf("[+] major:\t%d\n", in->major);
    printf("[+] minor:\t%d\n", in->minor);
    printf("[+] max_readahead:\t%d\n", in->max_readahead);
    printf("[+] flags:\t%x\n", in->flags);
}

void fuse_do_init(int fd)
{
    // 获取头部结构;
    char *buf = 0;
    buf = fuse_receive_req(fd);
    struct fuse_in_header *in = (struct fuse_in_header *)buf;
    // fuse_show_req_head(in);
    struct fuse_init_in *arg;
    arg = (struct fuse_init_in *)&in[1];
    fuse_show_init_in(arg);

    // 返回 参数
    struct fuse_init_out outarg;
    memset(&outarg, 0, sizeof(outarg));
    outarg.major = FUSE_KERNEL_VERSION;
    outarg.minor = FUSE_KERNEL_MINOR_VERSION;
    outarg.max_readahead = getpagesize() + 0x1000 - 4096;
    outarg.flags = 0x11;
    outarg.max_background = 0;
    outarg.congestion_threshold = 0;
    outarg.max_write = getpagesize() + 0x1000 - 4096;

    fuse_send_reply(fd, &outarg, sizeof(outarg), 0, in->unique);
}

void fuse_do_getattr(int fd)
{
    char *sbuf;
    struct fuse_in_header *in;
    sbuf = fuse_receive_req(fd);
    in = (struct fuse_in_header *)sbuf;
    // fuse_show_req_head(in);

    // 解析参数进行设置
    struct fuse_getattr_in *arg = (struct fuse_getattr_in *)&in[1];
    // struct fuse_file_info fi;
    // if (arg->getattr_flags & FUSE_GETATTR_FH)
    // {
    //     memset(&fi, 0, sizeof(fi));
    //     fi.fh = arg->fh;
    //     fi.fh_old = fi.fh;
    //     fip = &fi;
    // }

    // 设置返回值
    struct stat st;
    st.st_ino = in->nodeid;
    st.st_mode = S_IFREG | 04777;
    st.st_uid = 1000;
    st.st_gid = 1000;
    st.st_size = 100;

    struct fuse_attr_out outarg;
    memset(&outarg, 0, sizeof(outarg));
    outarg.attr_valid = 0;
    outarg.attr_valid_nsec = 0;

    convert_stat(&st, &outarg.attr);

    fuse_send_reply(fd, &outarg, sizeof(outarg), 0, in->unique);
}

void fuse_do_lookup(int fd)
{
    fflush(stdout);
    puts("-----------------------");
    puts("[+] start look up");
    char *sbuf;
    struct fuse_in_header *in;
    sbuf = fuse_receive_req(fd);
    in = (struct fuse_in_header *)sbuf;
    char *name = ((char *)&in[1]);
    printf("[+] lookup name: %s\n", name);

    struct fuse_entry_param e;
    memset(&e, 0, sizeof(struct fuse_entry_param)); // 清空内存
    e.ino = 5;
    e.generation = 1234;
    e.entry_timeout = 0;
    e.attr_timeout = 0;

    e.attr.st_ino = in->nodeid;
    e.attr.st_mode = S_IFREG | 0777;
    e.attr.st_uid = 1000;
    e.attr.st_gid = 1000;
    e.attr.st_size = 10000; // 长度太小？

    struct fuse_entry_out outarg;
    memset(&outarg, 0, sizeof(outarg));
    fill_entry(&outarg, &e);

    // getchar();
    printf("unique: %d\n", in->unique);
    fuse_send_reply(fd, &outarg, sizeof(outarg), 0, in->unique);
    puts("[+] end look_up");
}

void fuse_do_open(int fd)
{
    fflush(stdout);
    puts("-----------------------");
    puts("[+] start do_open");
    char *sbuf;
    struct fuse_in_header *in;
    sbuf = fuse_receive_req(fd);
    in = (struct fuse_in_header *)sbuf;
    struct fuse_open_in *inarg = (struct fuse_open_in *)&in[1];
    printf("[+] open flag : %x\n", inarg->flags);
    printf("[+] open unused : %x\n", inarg->unused);

    struct fuse_file_info fi;
    memset(&fi, 0, sizeof(fi));
    fi.flags = inarg->flags;

    fi.direct_io = 1; // 设置direct io 为 1

    struct fuse_open_out outarg;

    memset(&outarg, 0, sizeof(outarg));
    fill_open(&outarg, &fi);

    printf("unique: %d\n", in->unique);
    fuse_send_reply(fd, &outarg, sizeof(outarg), 0, in->unique);
    puts("[+] end do_open");
}

void fuse_do_read(int fd)
{
    fflush(stdout);
    puts("-----------------------");
    puts("[+] start do_read");
    char *sbuf;
    struct fuse_in_header *in;
    sbuf = fuse_receive_req(fd);
    in = (struct fuse_in_header *)sbuf;
    struct fuse_read_in *inarg = (struct fuse_read_in *)&in[1];

    struct fuse_bufvec *buf;
    void *mem;
    size_t size = inarg->size;

    char outarg[0x100];
    strcpy(outarg, "hello world!");

    printf("unique: %d\n", in->unique);
    fuse_send_reply(fd, outarg, strlen(outarg), 0, in->unique);
    puts("[+] end do_read");
}

void fuse_do_write(fd)
{
    fflush(stdout);
    puts("-----------------------");
    puts("[+] start do_write");

    // splice read requset from pipe
    puts("[+] create pipe");
    int pfd[2], ret;
    ret = pipe(pfd);
    if (ret < 0)
        fatal("pipe");
    size_t bufsize = getpagesize() + 0x1000;
    ret = splice(fd, NULL, pfd[1], NULL, bufsize, 0);
    if (ret < 0)
        fatal("splice");

    // 通过splice读取头部；
    struct fuse_in_header in;
    ret = read(pfd[0], &in, sizeof(struct fuse_in_header));
    if (ret < 0)
        fatal("read head");
    fuse_show_req_head(&in);

    puts("[+] send reply finish write");
    struct fuse_write_out outarg;
    outarg.size = 1;
    outarg.padding = 0;
    printf("unique: %d\n", in.unique);
    fuse_send_reply(fd, &outarg, sizeof(outarg), 0, in.unique);

    // 阻塞等待子进程释放page
    int t = 0;
    do
    {
        fflush(stdout);
        puts("[+] input 1 to contine, other to block");
        scanf("%d", &t);
        puts("[+] ...");

    } while (t != 1);

    struct fuse_write_in inarg;
    struct fuse_bufvec bufv;
    ret = read(pfd[0], &inarg, sizeof(struct fuse_write_in));
    if (ret < 0)
        fatal("read write in");
    /*
    struct fuse_write_in {
    __u64	fh;
    __u64	offset;
    __u32	size;
    __u32	write_flags;
    __u64	lock_owner;
    __u32	flags;
    __u32	padding;
};
    */
    printf("[+] write in:\n");
    printf("\tfh:\t%lld\n", inarg.fh);
    printf("\toffset:\t%lld\n", inarg.offset);
    printf("\tsize:\t%d\n", inarg.size);
    printf("\twrite_flags:\t%d\n", inarg.write_flags);
    printf("\tlock_owner:\t%llx\n", inarg.lock_owner);
    printf("\tflags:\t%d\n", inarg.flags);
    printf("\tpadding:\t%d\n", inarg.padding);

    ret = read(pfd[0], &bufv, sizeof(bufv)); //客户端write结束以后再读取page
    printf("bufv:\t%s\n", (char *)&bufv);

    puts("[+] end do_write");
    close(pfd[0]);
    close(pfd[1]);
}

int main(int argc, char const *argv[])
{
    int fd, pid;
    char buf[0x1000];
    create_ns();
    fd = fuse_dev_open(DEVNAME);
    mount_pfuse(fd); // 挂载fuse文件系统
    fuse_do_init(fd);
    pid = fork();
    if (pid == 0)
    {
        char *path[0x100];
        sprintf(path, "%s/file", MNT);
        puts(path);
        int fd = open(path, O_RDWR); // o只是阻塞了flash的刷新
        if (fd < 0)
            fatal("fuse open");

        puts("[++] start mmap");
        char *ptr = (char *)mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        fflush(stdout);
        if (ptr == 0)
            fatal("mmap failed");

        printf("[++] write msg : %s\n", ptr);
        memset(ptr, 'A', getpagesize());
        int ret = write(fd, ptr, 0x100); // 调用fuse_read
        fflush(stdout);
        if (ret < 0)
            // fatal("fuse write");
            puts("[--] write error");

        puts("[++] start munmap");
        memset(ptr, 'B', 0x10);
        ret = munmap(ptr, getpagesize());
        if (ret < 0)
            fatal("munmap error");
        // puts("[++] close hello");
        // close(hfd);
        puts("[++] child finish");
        return 0;
    }
    fuse_do_lookup(fd);
    fuse_do_open(fd);
    fuse_do_write(fd);
    fuse_receive_req(fd);
    // fuse_do_getattr(fd);

    kill(pid, SIGINT);
    waitpid(pid, NULL, 0);
    clear(fd); // 清理程序残留
    return 0;
}
