#import <Foundation/Foundation.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#ifndef CND_PRODUCTION_REFRESH_OUTPUT_TOKEN
#define CND_PRODUCTION_REFRESH_OUTPUT_TOKEN ""
#endif

#ifndef CND_PRODUCTION_REFRESH_OUTPUT_PATH
#define CND_PRODUCTION_REFRESH_OUTPUT_PATH \
    "/var/tmp/cyanide-production-refresh-trigger.log"
#endif

#ifndef CND_PRODUCTION_REFRESH_NONCE
#define CND_PRODUCTION_REFRESH_NONCE "0"
#endif

#ifndef CND_PRODUCTION_REFRESH_BUNDLE
#define CND_PRODUCTION_REFRESH_BUNDLE "com.apple.DocumentsApp"
#endif

typedef void (*CNDSetRefreshIdentifiersFunction)(NSArray<NSString *> *);
typedef NSDictionary<NSString *, id> *
    (*CNDRefreshSpringBoardFunction)(void);

static int gCNDProductionRefreshFD = -1;

static void CNDProductionRefreshLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDProductionRefreshLog(const char *format, ...)
{
    if (gCNDProductionRefreshFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = MIN((size_t)length, sizeof(line) - 1U);
    (void)write(gCNDProductionRefreshFD, line, amount);
    (void)fsync(gCNDProductionRefreshFD);
}

__attribute__((constructor))
static void CNDProductionRefreshStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_PRODUCTION_REFRESH_OUTPUT_TOKEN[0] && consume
            ? consume(CND_PRODUCTION_REFRESH_OUTPUT_TOKEN) : -1;
        gCNDProductionRefreshFD = open(
            CND_PRODUCTION_REFRESH_OUTPUT_PATH,
            O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
        if (gCNDProductionRefreshFD < 0) return;

        CNDSetRefreshIdentifiersFunction setIdentifiers =
            (CNDSetRefreshIdentifiersFunction)dlsym(
                RTLD_DEFAULT,
                "themer_set_springboard_iconservices_refresh_bundle_identifiers");
        CNDRefreshSpringBoardFunction refresh =
            (CNDRefreshSpringBoardFunction)dlsym(
                RTLD_DEFAULT,
                "CNDIconServicesConsumerLifecycleRefreshSpringBoardCaches");
        CNDProductionRefreshLog(
            "[CND_PRODUCTION_REFRESH] START pid=%d token=%lld main=%d "
            "nonce=%s setter=%p refresh=%p bundle=%s\n",
            getpid(), (long long)token,
            [NSThread isMainThread] ? 1 : 0,
            CND_PRODUCTION_REFRESH_NONCE, setIdentifiers, refresh,
            CND_PRODUCTION_REFRESH_BUNDLE);
        if (!setIdentifiers || !refresh) {
            CNDProductionRefreshLog(
                "[CND_PRODUCTION_REFRESH] COMPLETE nonce=%s ok=0 "
                "stage=symbol-resolution\n",
                CND_PRODUCTION_REFRESH_NONCE);
            return;
        }

        NSString *bundle = [NSString stringWithUTF8String:
            CND_PRODUCTION_REFRESH_BUNDLE];
        setIdentifiers(bundle.length > 0 ? @[bundle] : @[]);
        NSDictionary<NSString *, id> *result = refresh() ?: @{};
        NSData *json = [NSJSONSerialization dataWithJSONObject:result
                                                       options:0
                                                         error:nil];
        NSString *serialized = json
            ? [[NSString alloc] initWithData:json
                                    encoding:NSUTF8StringEncoding]
            : result.description;
        CNDProductionRefreshLog(
            "[CND_PRODUCTION_REFRESH] COMPLETE nonce=%s ok=%d result=%s\n",
            CND_PRODUCTION_REFRESH_NONCE,
            [result[@"ok"] boolValue] ? 1 : 0,
            serialized.UTF8String ?: "{}");
    }
}
