/*
 * Supervisor: spawns the controller via the launcher, ptrace-records the results of its
 * nondeterministic syscalls (trapped by the launcher's seccomp filter), periodically
 * CRIU-snapshots it, and on a fault alert (unix datagram socket) suspends it, restores
 * the newest snapshot and replays the trace recorded since that snapshot.
 *
 * Layout under --workdir:  sup.sock  controller.log  trace/NNNNNN.bin  snap/NNNNNN/
 * trace/N.bin holds everything recorded after snapshot N (N=0: since launch).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#ifndef PTRACE_EVENT_STOP
#define PTRACE_EVENT_STOP 128
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#define SYSINFO_ENTRY 1

#define TRACE_MAGIC "RRTRACE1"

static struct {
	const char *workdir, *launcher, *controller, *criu;
	int interval_ms, keep, use_criu, auto_replay, verbose;
	pid_t plant_pid;
} cfg = {"run", "build/launcher", "build/controller", "criu", 2000, 3, 1, 0, 0, 0};

static char sock_path[PATH_MAX], log_path[PATH_MAX];
static pid_t tpid;
static int alive, suspended, finished, final_rc = 1;
static enum { M_RECORD, M_REPLAY } mode;
static int gen, logfd = -1, alert_fd, snap_fd;
static unsigned nrec;
static volatile sig_atomic_t stop_req;

/* syscall currently being recorded/replayed */
static int pending;
static long cur_nr;
static uint64_t cur_args[6];

/* replay state: whole trace file in memory */
static unsigned char *rbuf;
static size_t rlen, roff, ent_off, ent_next;
static unsigned rcount, ridx;

struct ent_hdr {
	int32_t nr, nreg;
	int64_t ret;
	uint64_t args[6];
};
struct reg_hdr {
	uint64_t addr;
	uint32_t len, pad;
};
struct region {
	uint64_t addr;
	uint32_t len;
};

#define say(...) (printf("[sup] " __VA_ARGS__), fflush(stdout))

static void die(const char *m)
{
	perror(m);
	exit(1);
}

static void gen_path(char *out, const char *kind, int g, const char *suffix)
{
	snprintf(out, PATH_MAX, "%s/%s/%06d%s", cfg.workdir, kind, g, suffix);
}

static const char *sysname(long nr)
{
	switch (nr) {
	case SYS_read: return "read";
	case SYS_recvfrom: return "recvfrom";
	case SYS_clock_gettime: return "clock_gettime";
	case SYS_gettimeofday: return "gettimeofday";
	case SYS_time: return "time";
	case SYS_getrandom: return "getrandom";
	}
	return "?";
}

static int rm_cb(const char *p, const struct stat *s, int t, struct FTW *f)
{
	(void)s; (void)t; (void)f;
	return remove(p);
}
static void rm_rf(const char *p)
{
	nftw(p, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static int run_cmd(char *const argv[])
{
	pid_t p = fork();
	if (p == 0) {
		sigset_t e;
		sigemptyset(&e);
		sigprocmask(SIG_SETMASK, &e, NULL);
		/* criu 3.16 + glibc >= 2.35: criu's own rseq registration corrupts the restorer (SIGSEGV) */
		/* setenv("GLIBC_TUNABLES", "glibc.pthread.rseq=0", 1); */
		execvp(argv[0], argv);
		_exit(127);
	}
	int st;
	if (p < 0 || waitpid(p, &st, 0) < 0)
		return -1;
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* ---- tracee memory ---- */

static ssize_t mem_rw(int wr, uint64_t addr, void *buf, size_t len)
{
	char p[64];
	snprintf(p, sizeof p, "/proc/%d/mem", tpid);
	int fd = open(p, (wr ? O_WRONLY : O_RDONLY) | O_CLOEXEC); /* reopen: exec invalidates old fds */
	if (fd < 0)
		return -1;
	ssize_t r = wr ? pwrite(fd, buf, len, addr) : pread(fd, buf, len, addr);
	close(fd);
	return r;
}

/* Memory the kernel wrote for a syscall; this is the "result" we have to reproduce. */
static int out_regions(long nr, const uint64_t a[6], long ret, struct region r[2])
{
	int n = 0;
	switch (nr) {
	case SYS_read:
	case SYS_getrandom:
	case SYS_recvfrom:
		if (ret > 0) {
			r[n].addr = a[1];
			r[n++].len = (uint64_t)ret < a[2] ? (uint64_t)ret : a[2];
		}
		break;
	case SYS_clock_gettime:
		if (ret == 0)
			r[n++] = (struct region){a[1], 16};
		break;
	case SYS_gettimeofday:
		if (ret == 0) {
			if (a[0]) r[n++] = (struct region){a[0], 16};
			if (a[1]) r[n++] = (struct region){a[1], 8};
		}
		break;
	case SYS_time:
		if (a[0])
			r[n++] = (struct region){a[0], 8};
		break;
	}
	return n;
}

/* ---- trace files ---- */

static void trace_open(int g)
{
	char p[PATH_MAX];
	if (logfd >= 0)
		close(logfd);
	gen_path(p, "trace", g, ".bin");
	logfd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (logfd < 0 || write(logfd, TRACE_MAGIC, 8) != 8)
		die("trace_open");
	nrec = 0;
}

static void record_entry(long ret)
{
	struct region rg[2];
	int n = out_regions(cur_nr, cur_args, ret, rg);
	size_t sz = sizeof(struct ent_hdr);
	for (int i = 0; i < n; i++)
		sz += sizeof(struct reg_hdr) + rg[i].len;
	unsigned char *buf = calloc(1, sz), *w = buf;
	struct ent_hdr h = {.nr = cur_nr, .nreg = n, .ret = ret};
	memcpy(h.args, cur_args, sizeof h.args);
	memcpy(w, &h, sizeof h);
	w += sizeof h;
	for (int i = 0; i < n; i++) {
		struct reg_hdr rh = {.addr = rg[i].addr, .len = rg[i].len};
		memcpy(w, &rh, sizeof rh);
		w += sizeof rh;
		if (mem_rw(0, rg[i].addr, w, rg[i].len) < 0)
			memset(w, 0, rg[i].len);
		w += rg[i].len;
	}
	if (write(logfd, buf, sz) != (ssize_t)sz)
		perror("trace write");
	free(buf);
	nrec++;
	if (cfg.verbose)
		say("rec #%u %s = %ld\n", nrec, sysname(cur_nr), ret);
}

static size_t entry_end(size_t off)
{
	struct ent_hdr h;
	memcpy(&h, rbuf + off, sizeof h);
	off += sizeof h;
	for (int i = 0; i < h.nreg; i++) {
		struct reg_hdr rh;
		memcpy(&rh, rbuf + off, sizeof rh);
		off += sizeof rh + rh.len;
	}
	return off;
}

static int replay_load(int g)
{
	char p[PATH_MAX];
	gen_path(p, "trace", g, ".bin");
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) < 0)
		return -1;
	free(rbuf);
	rlen = st.st_size;
	rbuf = malloc(rlen);
	if (read(fd, rbuf, rlen) != (ssize_t)rlen || rlen < 8 || memcmp(rbuf, TRACE_MAGIC, 8)) {
		close(fd);
		return -1;
	}
	close(fd);
	rcount = 0;
	for (size_t o = 8; o < rlen; o = entry_end(o))
		rcount++;
	roff = 8;
	ridx = 0;
	return 0;
}

/* ---- tracee control ---- */

static void resume(int req, int sig)
{
	if (ptrace(req, tpid, 0, (void *)(long)sig) < 0 && errno != ESRCH)
		perror("ptrace resume");
}

static int alert_pending(void)
{
	struct pollfd p = {alert_fd, POLLIN, 0};
	return poll(&p, 1, 0) > 0 && (p.revents & POLLIN);
}

static void finish(int rc)
{
	finished = 1;
	final_rc = rc;
}

static void handle_alert(void);

/* Replay: validate the next log entry against the syscall the tracee just made. */
static int replay_check(void)
{
	if (ridx >= rcount) {
		if (alert_pending()) {
			handle_alert();
			return 0;
		}
		say("replay: trace exhausted (%u syscalls) and the fault did NOT occur\n", rcount);
		finish(1);
		return 0;
	}
	struct ent_hdr h;
	ent_off = roff;
	memcpy(&h, rbuf + ent_off, sizeof h);
	ent_next = entry_end(ent_off);
	if (h.nr != cur_nr || memcmp(h.args, cur_args, sizeof h.args)) {
		say("replay: DIVERGENCE at syscall #%u: trace has %s, tracee issued %s\n", ridx + 1,
		    sysname(h.nr), sysname(cur_nr));
		finish(2);
		return 0;
	}
	return 1;
}

static void replay_apply(struct user_regs_struct *r)
{
	struct ent_hdr h;
	size_t o = ent_off;
	memcpy(&h, rbuf + o, sizeof h);
	o += sizeof h;
	for (int i = 0; i < h.nreg; i++) {
		struct reg_hdr rh;
		memcpy(&rh, rbuf + o, sizeof rh);
		o += sizeof rh;
		mem_rw(1, rh.addr, rbuf + o, rh.len);
		o += rh.len;
	}
	r->rax = h.ret;
	ptrace(PTRACE_SETREGS, tpid, 0, r);
	ridx++;
	roff = ent_next;
	if (cfg.verbose)
		say("replay #%u %s = %ld\n", ridx, sysname(h.nr), (long)h.ret);
}

static void on_seccomp(void)
{
	struct user_regs_struct r;
	if (ptrace(PTRACE_GETREGS, tpid, 0, &r) < 0)
		return;
	cur_nr = r.orig_rax;
	cur_args[0] = r.rdi; cur_args[1] = r.rsi; cur_args[2] = r.rdx;
	cur_args[3] = r.r10; cur_args[4] = r.r8;  cur_args[5] = r.r9;
	if (mode == M_REPLAY) {
		if (!replay_check())
			return; /* tracee stays stopped */
		r.orig_rax = -1; /* skip the real syscall; result injected at exit stop */
		ptrace(PTRACE_SETREGS, tpid, 0, &r);
	}
	pending = 1;
	resume(PTRACE_SYSCALL, 0);
}

static void on_syscall_stop(void)
{
	unsigned char info[128];
	long n = ptrace(PTRACE_GET_SYSCALL_INFO, tpid, (void *)sizeof info, info);
	if (!pending) {
		resume(PTRACE_CONT, 0);
		return;
	}
	if (n > 0 && info[0] == SYSINFO_ENTRY) {
		resume(PTRACE_SYSCALL, 0);
		return;
	}
	struct user_regs_struct r;
	ptrace(PTRACE_GETREGS, tpid, 0, &r);
	if (mode == M_RECORD) {
		long ret = r.rax;
		/* kernel-internal restart codes (e.g. blocked read interrupted by our SIGSTOP):
		 * the syscall is re-issued and re-traced, so don't log this attempt */
		if (!(ret >= -516 && ret <= -512))
			record_entry(ret);
	} else {
		replay_apply(&r);
	}
	pending = 0;
	resume(PTRACE_CONT, 0);
}

static void handle_status(int st)
{
	if (WIFEXITED(st) || WIFSIGNALED(st)) {
		alive = 0;
		if (!finished) {
			say("controller exited unexpectedly (status 0x%x)\n", st);
			finish(3);
		}
		return;
	}
	if (!WIFSTOPPED(st))
		return;
	int sig = WSTOPSIG(st), ev = st >> 16;
	if (ev == PTRACE_EVENT_SECCOMP)
		on_seccomp();
	else if (sig == (SIGTRAP | 0x80))
		on_syscall_stop();
	else if (ev == PTRACE_EVENT_STOP)
		resume(PTRACE_CONT, 0);
	else
		resume(PTRACE_CONT, sig); /* signal-delivery-stop: pass the signal on */
}

static void drain_waits(void)
{
	int st;
	while (alive && !finished && waitpid(tpid, &st, WNOHANG | __WALL) > 0)
		handle_status(st);
}

/* Freeze the tracee in a signal-delivery-stop (we remain its tracer). */
static int stop_tracee(void)
{
	int st;
	if (suspended)
		return 0;
	kill(tpid, SIGSTOP);
	for (;;) {
		if (waitpid(tpid, &st, __WALL) < 0) {
			alive = 0;
			return -1;
		}
		if (WIFEXITED(st) || WIFSIGNALED(st)) {
			alive = 0;
			return -1;
		}
		if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSTOP && (st >> 16) == 0) {
			suspended = 1;
			return 0;
		}
		handle_status(st);
	}
}

static void reset_sigmask(void)
{
	sigset_t e;
	sigemptyset(&e);
	sigprocmask(SIG_SETMASK, &e, NULL);
}

static void launch(void)
{
	pid_t p = fork();
	if (p < 0)
		die("fork");
	if (p == 0) {
		reset_sigmask();
		execl(cfg.launcher, "launcher", log_path, cfg.controller, sock_path, (char *)NULL);
		perror("exec launcher");
		_exit(127);
	}
	int st;
	if (waitpid(p, &st, WUNTRACED) < 0 || !WIFSTOPPED(st)) {
		fprintf(stderr, "launcher failed (see %s)\n", log_path);
		exit(1);
	}
	tpid = p;
	alive = 1;
	suspended = pending = 0;
}

/* Attach to a stopped tracee (fresh launch or CRIU-restored) and let it run. */
static int attach_resume(void)
{
	long opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL;
	if (ptrace(PTRACE_SEIZE, tpid, 0, (void *)opts) < 0) {
		perror("PTRACE_SEIZE");
		return -1;
	}
	alive = 1;
	suspended = pending = 0;
	kill(tpid, SIGCONT);
	return 0;
}

/* ---- snapshots ---- */

static void wait_stopped(void)
{
	char p[64], buf[512];
	snprintf(p, sizeof p, "/proc/%d/stat", tpid);
	for (int i = 0; i < 3000; i++) {
		int fd = open(p, O_RDONLY | O_CLOEXEC);
		ssize_t n = fd >= 0 ? read(fd, buf, sizeof buf - 1) : -1;
		if (fd >= 0)
			close(fd);
		if (n > 0) {
			buf[n] = 0;
			char *c = strrchr(buf, ')');
			if (c && c[2] == 'T')
				return;
		}
		usleep(1000);
	}
}

static void take_snapshot(void)
{
	if (!alive || alert_pending())
		return;
	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	if (stop_tracee() < 0)
		return;
	if (alert_pending())
		return; /* fault in flight: leave it frozen, the main loop handles the alert */

	/* CRIU must seize the task itself, so hand it over in a plain group-stop. Nothing runs
	 * in between, so the filter never sees a traced syscall without a tracer. */
	ptrace(PTRACE_DETACH, tpid, 0, (void *)(long)SIGSTOP);
	suspended = 0;
	wait_stopped();

	int next = gen + 1;
	char tmp[PATH_MAX], fin[PATH_MAX], pidstr[16];
	snprintf(tmp, sizeof tmp, "%s/snap/.tmp", cfg.workdir);
	gen_path(fin, "snap", next, "");
	rm_rf(tmp);
	mkdir(tmp, 0755);
	snprintf(pidstr, sizeof pidstr, "%d", tpid);
	char *dump[] = {(char *)cfg.criu, "dump", "-t", pidstr, "-D", tmp, "--leave-running",
			"-o", "dump.log", "-v4", NULL};
	int rc = run_cmd(dump);
	if (rc == 0 && rename(tmp, fin) == 0) {
		unsigned old = nrec;
		gen = next;
		trace_open(gen);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		say("snapshot %d taken (%ld ms, %u syscalls recorded since previous)\n", gen,
		    (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000, old);
		char p[PATH_MAX];
		if (gen >= cfg.keep) {
			gen_path(p, "snap", gen - cfg.keep, "");
			rm_rf(p);
			gen_path(p, "trace", gen - cfg.keep, ".bin");
			unlink(p);
		}
	} else {
		say("criu dump failed (rc=%d), see %s/dump.log; keeping previous snapshot\n", rc, tmp);
	}
	attach_resume();
}

/* ---- fault handling / replay ---- */

static int plant_gone(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(ACT_PORT)};
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
	int ok = bind(fd, (struct sockaddr *)&a, sizeof a) == 0;
	close(fd);
	return ok;
}

static int do_replay(void)
{
	char dir[PATH_MAX];

	if (cfg.plant_pid > 0) {
		say("stopping plant (pid %d)\n", cfg.plant_pid);
		kill(cfg.plant_pid, SIGTERM);
	} else {
		say("stop the plant now (it still holds UDP port %d)\n", ACT_PORT);
	}
	for (int i = 0; !plant_gone(); i++) {
		if (i == 0)
			say("waiting for plant to exit...\n");
		usleep(200000);
	}
	say("plant is down: no external input can reach the controller from now on\n");
	if (!cfg.auto_replay) {
		say("press Enter to restore the last snapshot and replay the trace\n");
		char l[16];
		if (!fgets(l, sizeof l, stdin))
			return -1;
	}

	kill(tpid, SIGKILL);
	int st;
	while (waitpid(tpid, &st, __WALL) > 0 && !(WIFEXITED(st) || WIFSIGNALED(st)))
		;
	alive = suspended = pending = 0;
	if (logfd >= 0)
		close(logfd);
	logfd = -1;

	if (cfg.use_criu && gen > 0) {
		gen_path(dir, "snap", gen, "");
		say("restoring snapshot %d with CRIU\n", gen);
		/* -s: come back stopped so no traced syscall can run before we are attached */
		char *rst[] = {(char *)cfg.criu, "restore", "-D", dir, "-d", "-s", "-o", "restore.log",
			       "-v4", NULL};
		if (run_cmd(rst) != 0) {
			say("criu restore failed, see %s/restore.log\n", dir);
			return -1;
		}
		if (attach_resume() < 0)
			return -1;
		/* tracee is already running again: events are picked up by the main loop */
	} else {
		say("no snapshot yet: restarting controller from scratch (trace-0 covers the whole run)\n");
		launch();
		if (replay_load(gen) < 0)
			return -1;
		mode = M_REPLAY;
		return attach_resume();
	}
	if (replay_load(gen) < 0) {
		say("cannot load trace %d\n", gen);
		return -1;
	}
	mode = M_REPLAY;
	say("replaying trace-%06d: %u recorded syscalls\n", gen, rcount);
	return 0;
}

static void handle_alert(void)
{
	char msg[256];
	ssize_t n = recv(alert_fd, msg, sizeof msg - 1, MSG_DONTWAIT);
	if (n < 0)
		return;
	msg[n] = 0;
	if (mode == M_REPLAY) {
		say("FAULT REPRODUCED during replay after %u/%u syscalls: %s\n", ridx, rcount, msg);
		finish(0);
		return;
	}
	struct itimerspec z = {{0, 0}, {0, 0}};
	timerfd_settime(snap_fd, 0, &z, NULL);
	say("FAULT reported by controller: %s\n", msg);
	if (stop_tracee() < 0) {
		finish(1);
		return;
	}
	say("controller (pid %d) suspended; last snapshot=%d, %u syscalls recorded since\n", tpid, gen, nrec);
	if (do_replay() < 0)
		finish(1);
}

/* ---- main ---- */

static void on_term(int s)
{
	(void)s;
	stop_req = 1;
}

static void usage(const char *a)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"  --workdir DIR       state directory (default run)\n"
		"  --launcher PATH     (default build/launcher)\n"
		"  --controller PATH   (default build/controller)\n"
		"  --interval MS       snapshot period (default 2000)\n"
		"  --keep N            snapshots to keep (default 3)\n"
		"  --criu PATH         criu binary (default criu)\n"
		"  --no-criu           no snapshots; replay restarts the controller from scratch\n"
		"  --plant-pid PID     SIGTERM this plant on fault (else you are asked to stop it)\n"
		"  --auto-replay       don't wait for Enter before restoring\n"
		"  -v                  log every recorded/replayed syscall\n",
		a);
	exit(2);
}

int main(int argc, char **argv)
{
	static const struct option lo[] = {
		{"workdir", 1, 0, 'w'}, {"launcher", 1, 0, 'l'}, {"controller", 1, 0, 'c'},
		{"interval", 1, 0, 'i'}, {"keep", 1, 0, 'k'}, {"criu", 1, 0, 'C'},
		{"no-criu", 0, 0, 'n'}, {"plant-pid", 1, 0, 'p'}, {"auto-replay", 0, 0, 'a'},
		{0, 0, 0, 0}};
	int o;
	while ((o = getopt_long(argc, argv, "v", lo, NULL)) != -1) {
		switch (o) {
		case 'w': cfg.workdir = optarg; break;
		case 'l': cfg.launcher = optarg; break;
		case 'c': cfg.controller = optarg; break;
		case 'i': cfg.interval_ms = atoi(optarg); break;
		case 'k': cfg.keep = atoi(optarg); break;
		case 'C': cfg.criu = optarg; break;
		case 'n': cfg.use_criu = 0; break;
		case 'p': cfg.plant_pid = atoi(optarg); break;
		case 'a': cfg.auto_replay = 1; break;
		case 'v': cfg.verbose = 1; break;
		default: usage(argv[0]);
		}
	}
	if (cfg.use_criu && geteuid() != 0) {
		fprintf(stderr, "CRIU needs root: run with sudo, or pass --no-criu\n");
		return 1;
	}

	char p[PATH_MAX], rp[PATH_MAX];
	mkdir(cfg.workdir, 0755);
	if (!realpath(cfg.workdir, rp))
		die("workdir");
	cfg.workdir = strdup(rp);
	snprintf(p, sizeof p, "%s/trace", cfg.workdir);
	rm_rf(p);
	mkdir(p, 0755);
	snprintf(p, sizeof p, "%s/snap", cfg.workdir);
	rm_rf(p);
	mkdir(p, 0755);
	snprintf(sock_path, sizeof sock_path, "%s/sup.sock", cfg.workdir);
	snprintf(log_path, sizeof log_path, "%s/controller.log", cfg.workdir);
	unlink(log_path);
	if (realpath(cfg.launcher, rp)) cfg.launcher = strdup(rp);
	if (realpath(cfg.controller, rp)) cfg.controller = strdup(rp);

	alert_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	struct sockaddr_un sun = {.sun_family = AF_UNIX};
	if (strlen(sock_path) >= sizeof sun.sun_path) {
		fprintf(stderr, "workdir path too long for a unix socket\n");
		return 1;
	}
	strcpy(sun.sun_path, sock_path);
	unlink(sock_path);
	if (alert_fd < 0 || bind(alert_fd, (struct sockaddr *)&sun, sizeof sun) < 0)
		die("alert socket");

	sigset_t chld;
	sigemptyset(&chld);
	sigaddset(&chld, SIGCHLD);
	sigprocmask(SIG_BLOCK, &chld, NULL);
	int sig_fd = signalfd(-1, &chld, SFD_CLOEXEC | SFD_NONBLOCK);
	struct sigaction sa = {.sa_handler = on_term};
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	prctl(PR_SET_CHILD_SUBREAPER, 1);

	snap_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);

	launch();
	mode = M_RECORD;
	trace_open(0);
	if (attach_resume() < 0)
		return 1;
	say("controller pid %d recording (criu %s, snapshot every %d ms)\n", tpid,
	    cfg.use_criu ? "on" : "off", cfg.interval_ms);
	if (cfg.use_criu) {
		struct itimerspec its = {{cfg.interval_ms / 1000, cfg.interval_ms % 1000 * 1000000L},
					 {cfg.interval_ms / 1000, cfg.interval_ms % 1000 * 1000000L}};
		timerfd_settime(snap_fd, 0, &its, NULL);
	}

	while (!finished && !stop_req) {
		struct pollfd pf[3] = {{sig_fd, POLLIN, 0}, {alert_fd, POLLIN, 0}, {snap_fd, POLLIN, 0}};
		if (poll(pf, 3, -1) < 0)
			continue;
		if (pf[0].revents) {
			struct signalfd_siginfo si;
			while (read(sig_fd, &si, sizeof si) > 0)
				;
			drain_waits();
		}
		if (!finished && pf[1].revents & POLLIN)
			handle_alert();
		if (!finished && pf[2].revents & POLLIN) {
			uint64_t e;
			if (read(snap_fd, &e, sizeof e) > 0 && mode == M_RECORD)
				take_snapshot();
		}
	}

	if (stop_req && !finished)
		final_rc = 130;
	if (alive)
		kill(tpid, SIGKILL);
	if (mode == M_REPLAY && final_rc == 0)
		say("result: fault is deterministic given the recorded inputs\n");
	return final_rc;
}
