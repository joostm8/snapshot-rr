/*
 * launcher <logfile> <program> [args...]
 * Detaches into its own session, installs a raw-BPF seccomp filter that traps the
 * nondeterministic syscalls (SECCOMP_RET_TRACE), stops itself so the supervisor can
 * PTRACE_SEIZE it, then execs the program. The filter survives exec and CRIU dump/restore.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "common.h"

#ifndef __x86_64__
#error "filter is written for x86_64"
#endif

static void install_filter(void)
{
	static const int traced[] = {TRACED_SYSCALLS};
	const int n = sizeof traced / sizeof traced[0];
	struct sock_filter f[8 + 2 * n];
	int i = 0;

	f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
	f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
	/* reject the x32 ABI, which would otherwise dodge the number match */
	f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1);
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
	for (int k = 0; k < n; k++) {
		f[i++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, traced[k], 0, 1);
		f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE);
	}
	f[i++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

	struct sock_fprog prog = {.len = i, .filter = f};
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
	    syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) < 0) {
		perror("seccomp");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <logfile> <program> [args...]\n", argv[0]);
		return 2;
	}
	setsid(); /* CRIU needs a self-contained session */
	/* fixed addresses make a restart-from-scratch replay (--no-criu) deterministic */
	personality(personality(0xffffffff) | ADDR_NO_RANDOMIZE);

	int in = open("/dev/null", O_RDONLY);
	int out = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (in < 0 || out < 0) {
		perror("open");
		return 1;
	}
	dup2(in, 0);
	dup2(out, 1);
	dup2(out, 2);
	for (int fd = 3; fd < 1024; fd++)
		close(fd);

	install_filter();
	raise(SIGSTOP); /* supervisor attaches here, then SIGCONTs us */
	execv(argv[2], &argv[2]);
	perror("execv");
	return 127;
}
