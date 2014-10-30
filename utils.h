void daemonize(const char *progname);

void logmsg(int priority, const char *format, ...) __attribute__((format(printf, 2, 3)));
void logdbg(const char *format, ...) __attribute__((format(printf, 1, 2)));
void vlogmsg(int priority, const char *format, va_list ap);

void errexit(const char *format, ...) __attribute__((format(printf, 1, 2), noreturn));
void syserr(const char *fn) __attribute__((noreturn));

