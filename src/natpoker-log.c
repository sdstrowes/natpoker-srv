#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "natpoker-log.h"

#define BUF_LEN 2048
#define MAX_LEN (BUF_LEN - 1)

static int debug_enabled;

static void printf_log_func(int level, const char *msg)
{
	printf("%s\n", msg);
}

static void syslog_log_func(int level, const char *msg)
{
	syslog(level, "%s\n", msg);
}

typedef void (*log_func)(int level, const char *msg);
static log_func _log_func = printf_log_func;

void log_init(const char *id, int debug)
{
	_log_func = syslog_log_func;
	debug_enabled = debug;
	openlog(id, LOG_PERROR|LOG_PID|LOG_NDELAY, LOG_DAEMON);
	if (debug) {
		setlogmask(LOG_UPTO(LOG_INFO));
	}
	else {
		setlogmask(LOG_UPTO(LOG_ERR));
	}
	setvbuf(stdout, NULL, _IONBF, 0);
}

char *_log_msg_fmt(const char *fmt, ...)
{
	va_list args;
	char *msg = malloc(BUF_LEN);
	if (msg) {
		va_start(args, fmt);
		vsnprintf(msg, MAX_LEN, fmt, args);
		va_end(args);
	}
	return msg;
}

int _log_msg(const char *file, const char * func, int line, char *msg)
{
	char buf[BUF_LEN];
	snprintf(buf, MAX_LEN, "[%8.8s: %04u,%.16s] %s", file, line, func, msg);
	if (_log_func) {
		_log_func(LOG_INFO, buf);
	}
	free(msg);
	return 0;
}

int _log_err(const char *file, const char * func, int line, char *msg)
{
	char buf[BUF_LEN];
	snprintf(buf, MAX_LEN, "[%8.8s: %04u,%.16s] %s", file, line, func, msg);
	if (_log_func) {
		_log_func(LOG_ERR, buf);
	}
	free(msg);
	return 0;
}

