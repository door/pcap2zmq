/* -*- coding: utf-8-unix; -*- */
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>

#include "utils.h"


static int use_syslog = 0;


void
vlogmsg(int priority, const char *format, va_list ap)
{
        if(use_syslog) {
                vsyslog(priority, format, ap);
        } else {
                vfprintf(stderr, format, ap);
                fprintf(stderr, "\n");
        }
}


void
logmsg(int priority, const char *format, ...)
{
        va_list ap;
        va_start(ap, format);
        vlogmsg(priority, format, ap);
}


void
logdbg(const char *format, ...)
{
        va_list ap;
        va_start(ap, format);
        vlogmsg(LOG_DEBUG, format, ap);
}


void
errexit(const char *format, ...)
{
        va_list ap;
        va_start(ap, format);
        vlogmsg(LOG_ERR, format, ap);
        exit(EXIT_FAILURE);
}


void
syserr(const char *fn)
{
        errexit("Error occurred during %s: %s", fn, strerror(errno));
}


// (c) Devin Watson, Linux Daemon Writing HOWTO
void
daemonize(const char *progname)
{
        pid_t pid;

        /* already a daemon */
        if(1 == getppid())
                return;

        /* Fork off the parent process */
        pid = fork();
        if(-1 == pid)
                syserr("fork()");

        /* If we got a good PID, then we can exit the parent process. */
        if(pid > 0)
                exit(EXIT_SUCCESS);

        /* At this point we are executing as the child process */

        /* Change the file mode mask */
        umask(0600);

        /* Create a new SID for the child process */
        if(-1 == setsid())
                syserr("setsid()");

        /* Change the current working directory.  This prevents the current
           directory from being locked; hence not being able to remove it. */
        if((chdir("/")) < 0)
                syserr("chdir()");
        
        /* Redirect standard files to /dev/null */
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
        
        use_syslog = 1;
        
        openlog(progname, LOG_PID, LOG_DAEMON);
}
