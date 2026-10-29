/* PID controller. Knows nothing about snapshots, seccomp or tracing. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define KP 2.0
#define KI 1.0
#define KD 0.05
#define U_MAX 10.0
#define I_MAX 50.0

/* Raw syscall: glibc's clock_gettime goes through the vDSO and would be invisible to seccomp. */
static double mono(void)
{
	struct timespec ts;
	syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int udp_bind(int port)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
	if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) < 0) {
		perror("udp_bind");
		exit(1);
	}
	return fd;
}

static double clamp(double v, double lim)
{
	return v > lim ? lim : v < -lim ? -lim : v;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <supervisor-unix-socket>\n", argv[0]);
		return 2;
	}
	struct sockaddr_un sup = {.sun_family = AF_UNIX};
	strncpy(sup.sun_path, argv[1], sizeof sup.sun_path - 1);

	int rx = udp_bind(SENSOR_PORT);
	int tx = udp_bind(CTRL_TX_PORT);
	int alert = socket(AF_UNIX, SOCK_DGRAM, 0);
	int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	struct itimerspec its = {.it_interval = {0, TICK_NS}, .it_value = {0, TICK_NS}};
	timerfd_settime(tfd, 0, &its, NULL);

	struct sockaddr_in plant = {.sin_family = AF_INET, .sin_port = htons(ACT_PORT)};
	inet_pton(AF_INET, "127.0.0.1", &plant.sin_addr);

	double integral = 0, prev_err = 0, last_t = 0, u = 0;
	int have_last = 0;
	unsigned ticks = 0;
	fprintf(stderr, "[ctrl] pid %d up\n", getpid());

	for (;;) {
		uint64_t expirations;
		if (read(tfd, &expirations, sizeof expirations) != sizeof expirations)
			continue;
		ticks++;

		struct sensor_msg m, latest;
		int have = 0;
		while (recvfrom(rx, &m, sizeof m, MSG_DONTWAIT, NULL, NULL) == (ssize_t)sizeof m) {
			/* validate every queued reading: a backlog must not hide a bad one */
			if (!isfinite(m.measurement)) {
				char msg[128];
				int n = snprintf(msg, sizeof msg, "seq=%u non-finite measurement", m.seq);
				fprintf(stderr, "[ctrl] FAULT: %s\n", msg);
				sendto(alert, msg, n, 0, (struct sockaddr *)&sup, sizeof sup);
				for (;;)
					pause();
			}
			latest = m;
			have = 1;
		}
		if (!have)
			continue;

		double t = mono();
		double dt = have_last ? t - last_t : 0.01;
		if (dt <= 0)
			dt = 0.01;
		double err = latest.setpoint - latest.measurement;
		integral = clamp(integral + err * dt, I_MAX);
		double deriv = have_last ? (err - prev_err) / dt : 0;
		u = clamp(KP * err + KI * integral + KD * deriv, U_MAX);
		prev_err = err;
		last_t = t;
		have_last = 1;

		struct act_msg a = {.seq = latest.seq, .command = u};
		sendto(tx, &a, sizeof a, 0, (struct sockaddr *)&plant, sizeof plant);

		if (ticks % 50 == 0)
			fprintf(stderr, "[ctrl] seq=%u y=%.4f sp=%.2f u=%.4f\n", latest.seq,
				latest.measurement, latest.setpoint, u);
	}
}
