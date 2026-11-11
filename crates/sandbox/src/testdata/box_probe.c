#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    /* Unbuffered: every line is through the pipe the moment it is printed,
       so a held box reports live. The report does not wait for the exit the
       hold delays, and a lost release file still leaves the reader a report
       it can read. */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* The box's own cgroup as the kernel names it: 0::/ when the box stands
       at the root of its own cgroup namespace. */
    FILE *cg = fopen("/proc/self/cgroup", "r");
    char line[256];
    if (cg && fgets(line, sizeof line, cg)) {
        line[strcspn(line, "\n")] = 0;
        printf("self_cgroup: %s\n", line);
    } else {
        printf("self_cgroup: unreadable\n");
    }
    if (cg) fclose(cg);

    /* For the test to find in the box cgroup's own cgroup.procs. */
    printf("pid: %ld\n", (long)getpid());

    /* argv[i] names an operation on a path:
         STATFS:<path>  what filesystem is mounted there;
         READ:<path>    whether the path opens for reading;
         WRITE:<path>   whether the path opens for writing;
         MKDIR:<path>   whether a directory can be made there;
         NESTED:<name>  what a process of the box can do to cgroups from a
                        user, mount and cgroup namespace of its own, where
                        it is root and mounts cgroup2 itself: make a child
                        cgroup, and name the sibling box <name> to move into;
         MOUNTINFO:<path>  the mountinfo line of the mount on top of the
                        path: the box's /dev/pts, after its devpts remount;
         OPENPTY        whether the box's own user can open a PTY pair;
         HOLD:<path>    stay until that path appears, so the test can read
                        the host's side of the box's cgroup while the box is
                        still in it. The hold runs last, when every line of
                        the report is already out.
       and, for the IPC namespace proof:
         NS:<kind>      the namespace the box is in, /proc/self/ns/<kind>;
         SYSV:<key>     create a System V message queue, semaphore set and
                        shared memory segment under that key, removed again
                        at exit;
         SYSVGET:<key>  look the three up by key without creating them;
         MQ:<name>      create a POSIX message queue under that name, unlinked
                        again at exit (the raw syscall, which takes the name
                        without its leading slash, so no -lrt is needed);
         MQOPEN:<name>  open that queue without creating it;
         MARK:<path>    create that file, telling the test the operations
                        before it have run;
         EXIT:<code>    exit with that code at the end;
         KILL0:<signal> send that signal to the program's own process group;
         FDS            the descriptors the program has open. */
    const char *release = NULL;
    int exit_code = 0;
    int msq = -1, sem = -1, shm = -1;
    const char *mq = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "STATFS:", 7) == 0) {
            const char *path = argv[i] + 7;
            struct statfs st;
            if (statfs(path, &st) == 0)
                printf("fstype %s: magic %lu\n", path, (unsigned long)st.f_type);
            else
                printf("fstype %s: errno %d\n", path, errno);
        } else if (strncmp(argv[i], "READ:", 5) == 0) {
            const char *path = argv[i] + 5;
            int fd = open(path, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                printf("read %s: errno 0\n", path);
                close(fd);
            } else {
                printf("read %s: errno %d\n", path, errno);
            }
        } else if (strncmp(argv[i], "WRITE:", 6) == 0) {
            const char *path = argv[i] + 6;
            int fd = open(path, O_WRONLY | O_CLOEXEC);
            if (fd >= 0) {
                printf("open %s: errno 0\n", path);
                close(fd);
            } else {
                printf("open %s: errno %d\n", path, errno);
            }
        } else if (strncmp(argv[i], "MKDIR:", 6) == 0) {
            const char *path = argv[i] + 6;
            if (mkdir(path, 0700) == 0) {
                printf("mkdir %s: errno 0\n", path);
                rmdir(path);
            } else {
                printf("mkdir %s: errno %d\n", path, errno);
            }
        } else if (strncmp(argv[i], "NESTED:", 7) == 0) {
            const char *sibling = argv[i] + 7;
            long uid = (long)getuid(), gid = (long)getgid();
            fflush(stdout);
            pid_t child = fork();
            if (child == 0) {
                char buf[512];
                int fd;
                if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWCGROUP) != 0) {
                    printf("nested unshare: errno %d\n", errno);
                    _exit(0);
                }
                printf("nested unshare: errno 0\n");
                fd = open("/proc/self/setgroups", O_WRONLY);
                if (fd >= 0) { if (write(fd, "deny", 4) < 0) {} close(fd); }
                snprintf(buf, sizeof buf, "0 %ld 1", uid);
                fd = open("/proc/self/uid_map", O_WRONLY);
                if (fd >= 0) { if (write(fd, buf, strlen(buf)) < 0) {} close(fd); }
                snprintf(buf, sizeof buf, "0 %ld 1", gid);
                fd = open("/proc/self/gid_map", O_WRONLY);
                if (fd >= 0) { if (write(fd, buf, strlen(buf)) < 0) {} close(fd); }
                mkdir("/tmp/nested-cg", 0700);
                if (mount("cgroup2", "/tmp/nested-cg", "cgroup2", 0, NULL) != 0) {
                    printf("nested mount: errno %d\n", errno);
                    _exit(0);
                }
                printf("nested mount: errno 0\n");
                FILE *own = fopen("/proc/self/cgroup", "r");
                if (own && fgets(buf, sizeof buf, own)) {
                    buf[strcspn(buf, "\n")] = 0;
                    printf("nested self_cgroup: %s\n", buf);
                }
                if (own) fclose(own);
                /* Its own root is writable to it: the move is to where it is. */
                fd = open("/tmp/nested-cg/cgroup.procs", O_WRONLY);
                if (fd >= 0) {
                    printf("nested own procs: errno %d\n", write(fd, "0", 1) == 1 ? 0 : errno);
                    close(fd);
                } else {
                    printf("nested own procs: errno %d\n", errno);
                }
                printf("nested mkdir: errno %d\n", mkdir("/tmp/nested-cg/sub", 0700) == 0 ? 0 : errno);
                fd = open("/tmp/nested-cg/cgroup.max.descendants", O_WRONLY);
                if (fd >= 0) {
                    printf("nested raise descendants: errno %d\n", write(fd, "max", 3) == 3 ? 0 : errno);
                    close(fd);
                } else {
                    printf("nested raise descendants: errno %d\n", errno);
                }
                /* Every spelling that could name the sibling box. */
                const char *spellings[] = {"/tmp/nested-cg/%s/cgroup.procs",
                                           "/tmp/nested-cg/../%s/cgroup.procs",
                                           "/sys/fs/cgroup/../%s/cgroup.procs"};
                int reached = 0;
                for (int k = 0; k < 3; k++) {
                    snprintf(buf, sizeof buf, spellings[k], sibling);
                    fd = open(buf, O_WRONLY);
                    if (fd >= 0) {
                        if (write(fd, "0", 1) == 1) reached = 1;
                        close(fd);
                    }
                }
                printf("nested sibling reached: %d\n", reached);
                _exit(0);
            }
            int status;
            waitpid(child, &status, 0);
        } else if (strncmp(argv[i], "MOUNTINFO:", 10) == 0) {
            /* The last /proc/self/mountinfo line whose mount point is the
               path: the mount on top, its per-mount flags and its
               superblock options. */
            const char *path = argv[i] + 10;
            char found[1024] = "absent";
            char row[1024];
            FILE *mi = fopen("/proc/self/mountinfo", "r");
            while (mi && fgets(row, sizeof row, mi)) {
                char point[512];
                if (sscanf(row, "%*s %*s %*s %*s %511s", point) == 1 &&
                    strcmp(point, path) == 0) {
                    row[strcspn(row, "\n")] = 0;
                    snprintf(found, sizeof found, "%s", row);
                }
            }
            if (mi) fclose(mi);
            printf("mountinfo %s: %s\n", path, found);
        } else if (strcmp(argv[i], "OPENPTY") == 0) {
            /* Whether the box's own user can open a PTY pair: the master
               through /dev/ptmx, then the slave it names. */
            printf("openpty uid: %ld\n", (long)getuid());
            int master = posix_openpt(O_RDWR | O_NOCTTY);
            int err = 0;
            if (master < 0) {
                err = errno;
            } else if (grantpt(master) != 0 || unlockpt(master) != 0) {
                err = errno;
            } else {
                const char *name = ptsname(master);
                int slave = name ? open(name, O_RDWR | O_NOCTTY) : -1;
                if (slave < 0) err = name ? errno : ENOENT;
                else close(slave);
            }
            if (master >= 0) close(master);
            printf("openpty: errno %d\n", err);
        } else if (strncmp(argv[i], "HOLD:", 5) == 0) {
            release = argv[i] + 5;
        } else if (strncmp(argv[i], "NS:", 3) == 0) {
            char path[64], link[128];
            snprintf(path, sizeof path, "/proc/self/ns/%s", argv[i] + 3);
            ssize_t n = readlink(path, link, sizeof link - 1);
            if (n >= 0) {
                link[n] = 0;
                printf("ns %s: %s\n", argv[i] + 3, link);
            } else {
                printf("ns %s: errno %d\n", argv[i] + 3, errno);
            }
        } else if (strncmp(argv[i], "SYSV:", 5) == 0) {
            key_t key = (key_t)strtol(argv[i] + 5, NULL, 0);
            msq = msgget(key, IPC_CREAT | IPC_EXCL | 0600);
            printf("sysv create msg: errno %d\n", msq >= 0 ? 0 : errno);
            sem = semget(key, 1, IPC_CREAT | IPC_EXCL | 0600);
            printf("sysv create sem: errno %d\n", sem >= 0 ? 0 : errno);
            shm = shmget(key, 4096, IPC_CREAT | IPC_EXCL | 0600);
            printf("sysv create shm: errno %d\n", shm >= 0 ? 0 : errno);
        } else if (strncmp(argv[i], "SYSVGET:", 8) == 0) {
            key_t key = (key_t)strtol(argv[i] + 8, NULL, 0);
            printf("sysv get msg: errno %d\n", msgget(key, 0) >= 0 ? 0 : errno);
            printf("sysv get sem: errno %d\n", semget(key, 0, 0) >= 0 ? 0 : errno);
            printf("sysv get shm: errno %d\n", shmget(key, 0, 0) >= 0 ? 0 : errno);
        } else if (strncmp(argv[i], "MQ:", 3) == 0) {
            long fd = syscall(SYS_mq_open, argv[i] + 3, O_RDWR | O_CREAT | O_EXCL, 0600, NULL);
            printf("mq create: errno %d\n", fd >= 0 ? 0 : errno);
            if (fd >= 0) {
                mq = argv[i] + 3;
                close((int)fd);
            }
        } else if (strncmp(argv[i], "MQOPEN:", 7) == 0) {
            long fd = syscall(SYS_mq_open, argv[i] + 7, O_RDWR, 0, NULL);
            printf("mq open: errno %d\n", fd >= 0 ? 0 : errno);
            if (fd >= 0) close((int)fd);
        } else if (strncmp(argv[i], "KILL0:", 6) == 0) {
            /* A signal to the caller's own process group, which reaches
               every member of the group in whatever namespace it is. */
            int sig = atoi(argv[i] + 6);
            printf("kill0 %d: sending\n", sig);
            printf("kill0 %d: errno %d\n", sig, kill(0, sig) == 0 ? 0 : errno);
        } else if (strcmp(argv[i], "FDS") == 0) {
            /* The descriptors this program was started with. */
            DIR *fds = opendir("/proc/self/fd");
            printf("fds:");
            struct dirent *entry;
            while (fds && (entry = readdir(fds))) {
                int fd = atoi(entry->d_name);
                if (entry->d_name[0] != '.' && fd != dirfd(fds)) printf(" %d", fd);
            }
            printf("\n");
            if (fds) closedir(fds);
        } else if (strncmp(argv[i], "EXIT:", 5) == 0) {
            exit_code = atoi(argv[i] + 5);
        } else if (strncmp(argv[i], "MARK:", 5) == 0) {
            int fd = open(argv[i] + 5, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
            printf("mark: errno %d\n", fd >= 0 ? 0 : errno);
            if (fd >= 0) close(fd);
        }
    }

    /* 10s of waiting — shorter than the reader's deadline, so a lost release
       file is a box the reader still sees out, never a report that times
       out. */
    if (release) {
        for (int tries = 0; tries < 200 && access(release, F_OK) != 0; tries++) {
            struct timespec ts = {0, 50 * 1000 * 1000};
            nanosleep(&ts, 0);
        }
    }

    /* What SYSV: and MQ: created, removed so a run never leaves them behind
       in whatever IPC namespace the box was in. */
    if (msq >= 0) msgctl(msq, IPC_RMID, NULL);
    if (sem >= 0) semctl(sem, 0, IPC_RMID);
    if (shm >= 0) shmctl(shm, IPC_RMID, NULL);
    if (mq) syscall(SYS_mq_unlink, mq);
    return exit_code;
}
