
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
#include <stdint.h>
// 读取请求
struct fuse_in_header
{
    __u32 len;
    __u32 opcode;
    __u64 unique;
    __u64 nodeid;
    __u32 uid;
    __u32 gid;
    __u32 pid;
    __u32 padding;
};

struct fuse_out_header {
	__u32	len;
	__s32	error;
	__u64	unique;
};

enum fuse_opcode {
	FUSE_LOOKUP	   = 1,
	FUSE_FORGET	   = 2,  /* no reply */
	FUSE_GETATTR	   = 3,
	FUSE_SETATTR	   = 4,
	FUSE_READLINK	   = 5,
	FUSE_SYMLINK	   = 6,
	FUSE_MKNOD	   = 8,
	FUSE_MKDIR	   = 9,
	FUSE_UNLINK	   = 10,
	FUSE_RMDIR	   = 11,
	FUSE_RENAME	   = 12,
	FUSE_LINK	   = 13,
	FUSE_OPEN	   = 14,
	FUSE_READ	   = 15,
	FUSE_WRITE	   = 16,
	FUSE_STATFS	   = 17,
	FUSE_RELEASE       = 18,
	FUSE_FSYNC         = 20,
	FUSE_SETXATTR      = 21,
	FUSE_GETXATTR      = 22,
	FUSE_LISTXATTR     = 23,
	FUSE_REMOVEXATTR   = 24,
	FUSE_FLUSH         = 25,
	FUSE_INIT          = 26,
	FUSE_OPENDIR       = 27,
	FUSE_READDIR       = 28,
	FUSE_RELEASEDIR    = 29,
	FUSE_FSYNCDIR      = 30,
	FUSE_GETLK         = 31,
	FUSE_SETLK         = 32,
	FUSE_SETLKW        = 33,
	FUSE_ACCESS        = 34,
	FUSE_CREATE        = 35,
	FUSE_INTERRUPT     = 36,
	FUSE_BMAP          = 37,
	FUSE_DESTROY       = 38,
	FUSE_IOCTL         = 39,
	FUSE_POLL          = 40,
	FUSE_NOTIFY_REPLY  = 41,
	FUSE_BATCH_FORGET  = 42,
	FUSE_FALLOCATE     = 43,

	/* CUSE specific operations */
	CUSE_INIT          = 4096,
};

static struct {
	const char *name;
} fuse_ll_ops[] = {
	[FUSE_LOOKUP]	   = {       "LOOKUP"	     },
	[FUSE_FORGET]	   = {       "FORGET"	     },
	[FUSE_GETATTR]	   = {      "GETATTR"     },
	[FUSE_SETATTR]	   = {      "SETATTR"     },
	[FUSE_READLINK]	   = {     "READLINK"    },
	[FUSE_SYMLINK]	   = {  "SYMLINK"     },
	[FUSE_MKNOD]	   = { "MKNOD"	     },
	[FUSE_MKDIR]	   = { "MKDIR"	     },
	[FUSE_UNLINK]	   = { "UNLINK"	     },
	[FUSE_RMDIR]	   = { "RMDIR"	     },
	[FUSE_RENAME]	   = { "RENAME"	     },
	[FUSE_LINK]	   = { "LINK"	     },
	[FUSE_OPEN]	   = { "OPEN"	     },
	[FUSE_READ]	   = { "READ"	     },
	[FUSE_WRITE]	   = {"WRITE"	     },
	[FUSE_STATFS]	   = {"STATFS"	     },
	[FUSE_RELEASE]	   = {  "RELEASE"     },
	[FUSE_FSYNC]	   = {"FSYNC"	     },
	[FUSE_SETXATTR]	   = {"SETXATTR"    },
	[FUSE_GETXATTR]	   = { "GETXATTR"    },
	[FUSE_LISTXATTR]   = {  "LISTXATTR"   },
	[FUSE_REMOVEXATTR] = {"REMOVEXATTR" },
	[FUSE_FLUSH]	   = { "FLUSH"	     },
	[FUSE_INIT]	   = { "INIT"	     },
	[FUSE_OPENDIR]	   = { "OPENDIR"     },
	[FUSE_READDIR]	   = {"READDIR"     },
	[FUSE_RELEASEDIR]  = { "RELEASEDIR"  },
	[FUSE_FSYNCDIR]	   = {"FSYNCDIR"    },
	[FUSE_GETLK]	   = {"GETLK"	     },
	[FUSE_SETLK]	   = {"SETLK"	     },
	[FUSE_SETLKW]	   = {"SETLKW"	     },
	[FUSE_ACCESS]	   = {"ACCESS"	     },
	[FUSE_CREATE]	   = {"CREATE"	     },
	[FUSE_INTERRUPT]   = {"INTERRUPT"   },
	[FUSE_BMAP]	   = { "BMAP"	     },
	[FUSE_IOCTL]	   = { "IOCTL"	     },
	[FUSE_POLL]	   = {"POLL"	     },
	[FUSE_FALLOCATE]   = {"FALLOCATE"   },
	[FUSE_DESTROY]	   = { "DESTROY"     },
	[FUSE_NOTIFY_REPLY] = {"NOTIFY_REPLY" },
	[FUSE_BATCH_FORGET] = { "BATCH_FORGET" },
	[CUSE_INIT]	   = { "CUSE_INIT"   },
};

struct fuse_init_in {
	__u32	major;
	__u32	minor;
	__u32	max_readahead;
	__u32	flags;
};

struct fuse_init_out {
	__u32	major;
	__u32	minor;
	__u32	max_readahead;
	__u32	flags;
	__u16   max_background;
	__u16   congestion_threshold;
	__u32	max_write;
};

size_t iov_length(const struct iovec *iov, size_t count)
{
	size_t seg;
	size_t ret = 0;

	for (seg = 0; seg < count; seg++)
		ret += iov[seg].iov_len;
	return ret;
}

/** Version number of this interface */
#define FUSE_KERNEL_VERSION 7

/** Minor version number of this interface */
#define FUSE_KERNEL_MINOR_VERSION 19


struct fuse_getattr_in {
	__u32	getattr_flags;
	__u32	dummy;
	__u64	fh;
};

struct fuse_file_info {
	/** Open flags.	 Available in open() and release() */
	int flags;

	/** Old file handle, don't use */
	unsigned long fh_old;

	/** In case of a write operation indicates if this was caused by a
	    writepage */
	int writepage;

	/** Can be filled in by open, to use direct I/O on this file.
	    Introduced in version 2.4 */
	unsigned int direct_io : 1;

	/** Can be filled in by open, to indicate, that cached file data
	    need not be invalidated.  Introduced in version 2.4 */
	unsigned int keep_cache : 1;

	/** Indicates a flush operation.  Set in flush operation, also
	    maybe set in highlevel lock operation and lowlevel release
	    operation.	Introduced in version 2.6 */
	unsigned int flush : 1;

	/** Can be filled in by open, to indicate that the file is not
	    seekable.  Introduced in version 2.8 */
	unsigned int nonseekable : 1;

	/* Indicates that flock locks for this file should be
	   released.  If set, lock_owner shall contain a valid value.
	   May only be set in ->release().  Introduced in version
	   2.9 */
	unsigned int flock_release : 1;

	/** Padding.  Do not use*/
	unsigned int padding : 27;

	/** File handle.  May be filled in by filesystem in open().
	    Available in all other file operations */
	uint64_t fh;

	/** Lock owner id.  Available in locking operations and flush */
	uint64_t lock_owner;
};
struct fuse_attr {
	__u64	ino;
	__u64	size;
	__u64	blocks;
	__u64	atime;
	__u64	mtime;
	__u64	ctime;
	__u32	atimensec;
	__u32	mtimensec;
	__u32	ctimensec;
	__u32	mode;
	__u32	nlink;
	__u32	uid;
	__u32	gid;
	__u32	rdev;
	__u32	blksize;
	__u32	padding;
};

struct fuse_attr_out {
	__u64	attr_valid;	/* Cache timeout for the attributes */
	__u32	attr_valid_nsec;
	__u32	dummy;
	struct fuse_attr attr;
};

static void convert_stat(const struct stat *stbuf, struct fuse_attr *attr)
{
	attr->ino	= stbuf->st_ino;
	attr->mode	= stbuf->st_mode;
	attr->nlink	= stbuf->st_nlink;
	attr->uid	= stbuf->st_uid;
	attr->gid	= stbuf->st_gid;
	attr->rdev	= stbuf->st_rdev;
	attr->size	= stbuf->st_size;
	attr->blksize	= stbuf->st_blksize;
	attr->blocks	= stbuf->st_blocks;
	attr->atime	= stbuf->st_atime;
	attr->mtime	= stbuf->st_mtime;
	attr->ctime	= stbuf->st_ctime;
	attr->atimensec = 0;
	attr->mtimensec = 0;
	attr->ctimensec = 0;
}

struct fuse_entry_out {
	__u64	nodeid;		/* Inode ID */
	__u64	generation;	/* Inode generation: nodeid:gen must
				   be unique for the fs's lifetime */
	__u64	entry_valid;	/* Cache timeout for the name */
	__u64	attr_valid;	/* Cache timeout for the attributes */
	__u32	entry_valid_nsec;
	__u32	attr_valid_nsec;
	struct fuse_attr attr;
};

typedef unsigned long fuse_ino_t;
/** Directory entry parameters supplied to fuse_reply_entry() */
struct fuse_entry_param {
	/** Unique inode number
	 *
	 * In lookup, zero means negative entry (from version 2.5)
	 * Returning ENOENT also means negative entry, but by setting zero
	 * ino the kernel may cache negative entries for entry_timeout
	 * seconds.
	 */
	fuse_ino_t ino;

	/** Generation number for this entry.
	 *
	 * If the file system will be exported over NFS, the
	 * ino/generation pairs need to be unique over the file
	 * system's lifetime (rather than just the mount time). So if
	 * the file system reuses an inode after it has been deleted,
	 * it must assign a new, previously unused generation number
	 * to the inode at the same time.
	 *
	 * The generation must be non-zero, otherwise FUSE will treat
	 * it as an error.
	 *
	 */
	unsigned long generation;

	/** Inode attributes.
	 *
	 * Even if attr_timeout == 0, attr must be correct. For example,
	 * for open(), FUSE uses attr.st_size from lookup() to determine
	 * how many bytes to request. If this value is not correct,
	 * incorrect data will be returned.
	 */
	struct stat attr;

	/** Validity timeout (in seconds) for the attributes */
	double attr_timeout;

	/** Validity timeout (in seconds) for the name */
	double entry_timeout;
};

static void fill_entry(struct fuse_entry_out *arg,
		       const struct fuse_entry_param *e)
{
	arg->nodeid = e->ino;
	arg->generation = e->generation;
	arg->entry_valid = 1;
	arg->entry_valid_nsec = 1;
	arg->attr_valid = 1;
	arg->attr_valid_nsec = 1;
	convert_stat(&e->attr, &arg->attr);
}

/**
 * Flags returned by the OPEN request
 *
 * FOPEN_DIRECT_IO: bypass page cache for this open file
 * FOPEN_KEEP_CACHE: don't invalidate the data cache on open
 * FOPEN_NONSEEKABLE: the file is not seekable
 */
#define FOPEN_DIRECT_IO		(1 << 0)
#define FOPEN_KEEP_CACHE	(1 << 1)
#define FOPEN_NONSEEKABLE	(1 << 2)

struct fuse_open_in {
	__u32	flags;
	__u32	unused;
};

struct fuse_open_out {
	__u64	fh;
	__u32	open_flags;
	__u32	padding;
};

static void fill_open(struct fuse_open_out *arg,
		      const struct fuse_file_info *f)
{
	arg->fh = f->fh;
	if (f->direct_io)
		arg->open_flags |= FOPEN_DIRECT_IO;
	if (f->keep_cache)
		arg->open_flags |= FOPEN_KEEP_CACHE;
	if (f->nonseekable)
		arg->open_flags |= FOPEN_NONSEEKABLE;
}


struct fuse_read_in {
	__u64	fh;
	__u64	offset;
	__u32	size;
	__u32	read_flags;
	__u64	lock_owner;
	__u32	flags;
	__u32	padding;
};

/* ----------------------------------------------------------- *
 * Data buffer						       *
 * ----------------------------------------------------------- */

/**
 * Buffer flags
 */
enum fuse_buf_flags {
	/**
	 * Buffer contains a file descriptor
	 *
	 * If this flag is set, the .fd field is valid, otherwise the
	 * .mem fields is valid.
	 */
	FUSE_BUF_IS_FD		= (1 << 1),

	/**
	 * Seek on the file descriptor
	 *
	 * If this flag is set then the .pos field is valid and is
	 * used to seek to the given offset before performing
	 * operation on file descriptor.
	 */
	FUSE_BUF_FD_SEEK	= (1 << 2),

	/**
	 * Retry operation on file descriptor
	 *
	 * If this flag is set then retry operation on file descriptor
	 * until .size bytes have been copied or an error or EOF is
	 * detected.
	 */
	FUSE_BUF_FD_RETRY	= (1 << 3),
};

/**
 * Buffer copy flags
 */
enum fuse_buf_copy_flags {
	/**
	 * Don't use splice(2)
	 *
	 * Always fall back to using read and write instead of
	 * splice(2) to copy data from one file descriptor to another.
	 *
	 * If this flag is not set, then only fall back if splice is
	 * unavailable.
	 */
	FUSE_BUF_NO_SPLICE	= (1 << 1),

	/**
	 * Force splice
	 *
	 * Always use splice(2) to copy data from one file descriptor
	 * to another.  If splice is not available, return -EINVAL.
	 */
	FUSE_BUF_FORCE_SPLICE	= (1 << 2),

	/**
	 * Try to move data with splice.
	 *
	 * If splice is used, try to move pages from the source to the
	 * destination instead of copying.  See documentation of
	 * SPLICE_F_MOVE in splice(2) man page.
	 */
	FUSE_BUF_SPLICE_MOVE	= (1 << 3),

	/**
	 * Don't block on the pipe when copying data with splice
	 *
	 * Makes the operations on the pipe non-blocking (if the pipe
	 * is full or empty).  See SPLICE_F_NONBLOCK in the splice(2)
	 * man page.
	 */
	FUSE_BUF_SPLICE_NONBLOCK= (1 << 4),
};


/**
 * Single data buffer
 *
 * Generic data buffer for I/O, extended attributes, etc...  Data may
 * be supplied as a memory pointer or as a file descriptor
 */
struct fuse_buf {
	/**
	 * Size of data in bytes
	 */
	size_t size;

	/**
	 * Buffer flags
	 */
	enum fuse_buf_flags flags;

	/**
	 * Memory pointer
	 *
	 * Used unless FUSE_BUF_IS_FD flag is set.
	 */
	void *mem;

	/**
	 * File descriptor
	 *
	 * Used if FUSE_BUF_IS_FD flag is set.
	 */
	int fd;

	/**
	 * File position
	 *
	 * Used if FUSE_BUF_FD_SEEK flag is set.
	 */
	off_t pos;
};

/**
 * Data buffer vector
 *
 * An array of data buffers, each containing a memory pointer or a
 * file descriptor.
 *
 * Allocate dynamically to add more than one buffer.
 */
struct fuse_bufvec {
	/**
	 * Number of buffers in the array
	 */
	size_t count;

	/**
	 * Index of current buffer within the array
	 */
	size_t idx;

	/**
	 * Current offset within the current buffer
	 */
	size_t off;

	/**
	 * Array of buffers
	 */
	struct fuse_buf buf[1];
};

/* Initialize bufvec with a single buffer of given size */
#define FUSE_BUFVEC_INIT(size__) 				\
	((struct fuse_bufvec) {					\
		/* .count= */ 1,				\
		/* .idx =  */ 0,				\
		/* .off =  */ 0,				\
		/* .buf =  */ { /* [0] = */ {			\
			/* .size =  */ (size__),		\
			/* .flags = */ (enum fuse_buf_flags) 0,	\
			/* .mem =   */ NULL,			\
			/* .fd =    */ -1,			\
			/* .pos =   */ 0,			\
		} }						\
	} )


struct fuse_write_in {
	__u64	fh;
	__u64	offset;
	__u32	size;
	__u32	write_flags;
	__u64	lock_owner;
	__u32	flags;
	__u32	padding;
};

struct fuse_write_out {
	__u32	size;
	__u32	padding;
};
