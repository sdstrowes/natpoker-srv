#ifndef _NATPOKER_LOG_H_
#define _NATPOKER_LOG_H_

#include <stdlib.h>
#include <string.h>

#define FILE (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

void log_init(const char *id, int debug);

char *_log_msg_fmt(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

int _log_msg(const char *file, const char * func, int line, char *msg);
int _log_err(const char *file, const char * func, int line, char *msg);

#define log_msg(...) \
	_log_msg(FILE, __FUNCTION__, __LINE__, _log_msg_fmt(__VA_ARGS__))

#define log_err(...) \
	_log_err(FILE, __FUNCTION__, __LINE__, _log_msg_fmt(__VA_ARGS__))

#endif

