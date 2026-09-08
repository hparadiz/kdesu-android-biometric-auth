/* SPDX-License-Identifier: MIT
 * Small setuid entry point. No request content is interpreted by this launcher.
 * The installed verifier owns policy, biometric verification and exact execution.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int fail(const char *message)
{
    fprintf(stderr, "Navi authorization: %s\n", message);
    return 1;
}

int main(int argc, char **argv)
{
    (void)argv;
    const int error_flags = fcntl(STDERR_FILENO, F_GETFL);
    if (error_flags >= 0)
        fcntl(STDERR_FILENO, F_SETFL, error_flags | O_NONBLOCK);
    const uid_t caller = getuid();
    struct stat input, output;
    if (argc != 1 || caller == 0 || geteuid() != 0)
        return fail("use the installed helper from the desktop account");
    if (fstat(STDIN_FILENO, &input) || fstat(STDOUT_FILENO, &output)
        || !S_ISFIFO(input.st_mode) || !S_ISFIFO(output.st_mode))
        return fail("standard input and output must be private process pipes");

    char uid[32];
    if (snprintf(uid, sizeof(uid), "%lu", (unsigned long)caller) >= (int)sizeof(uid))
        return fail("invalid invoking account");
    if (clearenv() || setgroups(0, NULL) || setresgid(0, 0, 0) || setresuid(0, 0, 0) || chdir("/"))
        return fail("could not establish the protected execution environment");
    if (close_range(3, UINT_MAX, 0) != 0)
        return fail("could not close inherited file descriptors");
    const struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core))
        return fail("could not disable core dumps");
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL))
        return fail("could not reset the signal mask");
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    for (int sig = 1; sig < NSIG; ++sig)
        if (sig != SIGKILL && sig != SIGSTOP)
            sigaction(sig, &action, NULL);
    umask(0077);
    alarm(180); /* Absolute process lifetime, including shutdown after a lost GUI. */
    char *const arguments[] = {"/usr/bin/python3.14", "-I",
        "/usr/libexec/navi-auth/rootauth.py", "--stdio", uid, NULL};
    char *const environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8", NULL};
    execve(arguments[0], arguments, environment);
    return fail("could not start the installed verifier");
}
