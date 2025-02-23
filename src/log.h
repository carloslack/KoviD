#ifndef __LOG_H
#define __LOG_H

#ifdef DEBUG_RING_BUFFER

#define prinfo(fmt, ...) pr_info(fmt, ##__VA_ARGS__);
#define prwarn(fmt, ...) pr_warn(fmt, ##__VA_ARGS__);
#define prerr(fmt, ...) pr_err(fmt, ##__VA_ARGS__);
#define premerg(fmt, ...) pr_emerg(fmt, ##__VA_ARGS__);
#define pralert(fmt, ...) pr_alert(fmt, ##__VA_ARGS__);
#define prcrit(fmt, ...) prcrit(fmt, ##__VA_ARGS__);
#define prnotice(fmt, ...) prnotice(fmt, ##__VA_ARGS__);
#define prinfo_ratelimited(fmt, ...) pr_info_ratelimited(fmt, ##__VA_ARGS__);
#define prwarn_ratelimited(fmt, ...) pr_warn_ratelimited(fmt, ##__VA_ARGS__);
#define prerr_ratelimited(fmt, ...) pr_err_ratelimited(fmt, ##__VA_ARGS__);
#define prinfo_once(fmt, ...) pr_info_once(fmt, ##__VA_ARGS__);
#define prwarn_once(fmt, ...) pr_warn_once(fmt, ##__VA_ARGS__);
#define prerr_once(fmt, ...) pr_err_once(fmt, ##__VA_ARGS__);

//  _testlog: macros for logging test-related information.
//
//  Used for testing purposes and prefixes log messages with, suggestion,
//  "<test name>:<component name>" and the provided module name.
//  The format string and additional
//  arguments follow the standard `pr_` logging mechanism.
//
//  Once this macro is used in the code (or modified from the standard,
//  example,`prinfo`), any further modifications to its content
//  should be agreed upon with the testers.
//
//  module: The name of the module or test name (e.g., "my_module") to be included in the log.
//  fmt: The format string for the log message, followed by any additional arguments.
//  Example:
//	prinfo_testlog("print_test", "sys", "running\n");
#define prinfo_testlog(test, module, fmt, ...)                                 \
	pr_info("%s:%s: " fmt, test, module, ##__VA_ARGS__);
#define prwarn_testlog(test, module, fmt, ...)                                 \
	pr_warn("%s:%s: " fmt, test, module, ##__VA_ARGS__);
#define prerr_testlog(test, module, fmt, ...)                                  \
	pr_err("%s:%s: " fmt, test, module, ##__VA_ARGS__);

#else

// Quiet
#define prinfo(fmt, ...)                                                       \
	do {                                                                   \
	} while (0)
#define prwarn(fmt, ...)                                                       \
	do {                                                                   \
	} while (0)
#define premerg(fmt, ...)                                                      \
	do {                                                                   \
	} while (0)
#define pralert(fmt, ...)                                                      \
	do {                                                                   \
	} while (0)
#define prcrit(fmt, ...)                                                       \
	do {                                                                   \
	} while (0)
#define prnotice(fmt, ...)                                                     \
	do {                                                                   \
	} while (0)
#define prerr(fmt, ...)                                                        \
	do {                                                                   \
	} while (0)
#define prwarn_ratelimited(fmt, ...)                                           \
	do {                                                                   \
	} while (0)
#define prinfo_ratelimited(fmt, ...)                                           \
	do {                                                                   \
	} while (0)
#define prerr_ratelimited(fmt, ...)                                            \
	do {                                                                   \
	} while (0)
#define prinfo_once(fmt, ...)                                                  \
	do {                                                                   \
	} while (0)
#define prwarn_once(fmt, ...)                                                  \
	do {                                                                   \
	} while (0)
#define prerr_once(fmt, ...)                                                   \
	do {                                                                   \
	} while (0)
#define prinfo_testlog(fmt, ...)                                               \
	do {                                                                   \
	} while (0)
#define prwarn_testlog(fmt, ...)                                               \
	do {                                                                   \
	} while (0)
#define prerr_testlog(fmt, ...)                                                \
	do {                                                                   \
	} while (0)
#endif

#endif
