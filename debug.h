#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#ifdef SYSLOG
#include <syslog.h>
#endif


#ifdef SYSLOG
# define LOG(level, str, args...) syslog(level, str, ## args)
#else
# define LOG_EMERG	"EMERGENCY!"
# define LOG_ALERT	"ALERT!"
# define LOG_CRIT	"critical!"
# define LOG_WARNING	"warning"
# define LOG_ERR	"error"
# define LOG_INFO	"info"
# define LOG_DEBUG	"debug"
# define LOG(level, str, args...) do { printf("%s, ", level); \
				printf(str, ## args); \
				printf("\n"); } while(0)
#endif

#ifdef DEBUG
# undef DEBUG
# define DEBUG(level, str, args...) LOG(level, str, ## args)
# define DEBUGGING
#else
# define DEBUG(level, str, args...)
#endif

#endif