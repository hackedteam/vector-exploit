//#define DEBUG

#include <errno.h>
#include <string.h>
// can't use liblog.so because this is a static binary, so we need
// to implement this ourselves
#include <android/log.h>

#ifdef DEBUG
#warning "Debug mode is enabled, errors will be printed to stdout"
#define LOG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define LOGE(fmt,args...) exec_log(ANDROID_LOG_ERROR, fmt, ##args)
#define LOGW(fmt,args...) exec_log(ANDROID_LOG_WARN, fmt, ##args)
#define LOGD(fmt,args...) exec_log(ANDROID_LOG_DEBUG, fmt, ##args)
#define LOGV(fmt,args...) exec_log(ANDROID_LOG_VERBOSE, fmt, ##args)
#else
#define LOG(fmt, ...);
#define LOGE(fmt, ...); 
#define LOGW(fmt, ...);
#define LOGD(fmt, ...);
#define LOGV(fmt, ...);
#endif

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "su"

#define PLOGE(fmt,args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#define PLOGEV(fmt,err,args...) LOGE(fmt " failed with %d: %s", ##args, err, strerror(err))

void exec_log(int priority, const char* fmt, ...);

