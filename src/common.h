#pragma once
#include <stdint.h>
#include <sys/syscall.h>

#define SENSOR_PORT  9000  /* plant -> controller */
#define ACT_PORT     9001  /* controller -> plant */
#define CTRL_TX_PORT 9002  /* controller's source port for actuator datagrams */
#define TICK_NS      10000000L /* 100 Hz */

struct __attribute__((packed)) sensor_msg {
	uint32_t seq;
	double measurement;
	double setpoint;
};

struct __attribute__((packed)) act_msg {
	uint32_t seq;
	double command;
};

/* Syscalls whose results are nondeterministic; the seccomp filter traps exactly these. */
/* Nondeterministic inputs (results are recorded) plus sendto (payload is recorded and verified on replay). */
#define TRACED_SYSCALLS \
	SYS_read, SYS_recvfrom, SYS_clock_gettime, SYS_gettimeofday, SYS_time, SYS_getrandom, SYS_sendto
