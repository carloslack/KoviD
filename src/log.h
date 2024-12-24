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

#else

/** Quiet */
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
#endif

#endif
