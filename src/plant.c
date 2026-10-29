/*
 * Simulated first-order plant. Sends sensor readings at 100 Hz to the controller over UDP
 * and integrates the actuator commands it gets back.
 * Keys: f = inject poison (NaN) reading, +/- = change setpoint, q = quit.
 * --fault-after S injects the poison automatically after S seconds.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <termios.h>
#include <unistd.h>

#include "common.h"

#define TAU 0.5

static volatile sig_atomic_t quit;
static struct termios saved_tio;
static int tio_saved;

static void on_sig(int s)
{
	(void)s;
	quit = 1;
}

static void restore_tty(void)
{
	if (tio_saved)
		tcsetattr(0, TCSANOW, &saved_tio);
}

int main(int argc, char **argv)
{
	double fault_after = -1;
	for (int i = 1; i + 1 < argc; i++)
		if (!strcmp(argv[i], "--fault-after"))
			fault_after = atof(argv[i + 1]);

	struct sigaction sa = {.sa_handler = on_sig};
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (isatty(0) && tcgetattr(0, &saved_tio) == 0) {
		struct termios raw = saved_tio;
		raw.c_lflag &= ~(ICANON | ECHO);
		tcsetattr(0, TCSANOW, &raw);
		tio_saved = 1;
		atexit(restore_tty);
	}

	int rx = socket(AF_INET, SOCK_DGRAM, 0);
	int tx = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in me = {.sin_family = AF_INET, .sin_port = htons(ACT_PORT)};
	struct sockaddr_in ctrl = {.sin_family = AF_INET, .sin_port = htons(SENSOR_PORT)};
	inet_pton(AF_INET, "127.0.0.1", &me.sin_addr);
	inet_pton(AF_INET, "127.0.0.1", &ctrl.sin_addr);
	if (bind(rx, (struct sockaddr *)&me, sizeof me) < 0) {
		perror("bind");
		return 1;
	}

	int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	struct itimerspec its = {.it_interval = {0, TICK_NS}, .it_value = {0, TICK_NS}};
	timerfd_settime(tfd, 0, &its, NULL);

	double x = 0, u = 0, sp = 1.0, dt = TICK_NS * 1e-9;
	uint32_t seq = 0;
	int poison = 0, auto_fired = 0, stdin_open = 1;
	printf("[plant] running; keys: f=poison  +/-=setpoint  q=quit\n");
	fflush(stdout);

	while (!quit) {
		struct pollfd p[3] = {{tfd, POLLIN, 0}, {rx, POLLIN, 0}, {stdin_open ? 0 : -1, POLLIN, 0}};
		if (poll(p, 3, -1) < 0)
			continue;

		if (p[1].revents & POLLIN) {
			struct act_msg a;
			while (recv(rx, &a, sizeof a, MSG_DONTWAIT) == (ssize_t)sizeof a)
				u = a.command;
		}
		if (p[2].revents & (POLLIN | POLLHUP)) {
			char c;
			if (read(0, &c, 1) <= 0)
				stdin_open = 0;
			else if (c == 'f')
				poison = 1;
			else if (c == '+')
				sp += 0.5;
			else if (c == '-')
				sp -= 0.5;
			else if (c == 'q')
				quit = 1;
		}
		if (p[0].revents & POLLIN) {
			uint64_t e;
			if (read(tfd, &e, sizeof e) != sizeof e)
				continue;
			x += dt * (-x + u) / TAU;
			seq++;
			if (fault_after >= 0 && !auto_fired && seq * dt >= fault_after) {
				poison = auto_fired = 1;
			}
			struct sensor_msg m = {.seq = seq, .measurement = poison ? NAN : x, .setpoint = sp};
			if (poison) {
				printf("[plant] sending POISON reading (seq=%u)\n", seq);
				fflush(stdout);
				poison = 0;
			}
			sendto(tx, &m, sizeof m, 0, (struct sockaddr *)&ctrl, sizeof ctrl);
			if (seq % 50 == 0) {
				printf("[plant] seq=%u y=%.4f sp=%.2f u=%.4f\n", seq, x, sp, u);
				fflush(stdout);
			}
		}
	}
	printf("[plant] stopped\n");
	return 0;
}
