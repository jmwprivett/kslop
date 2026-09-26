#import <Foundation/Foundation.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#ifndef CND_APPLIED_ICON_AUDIT_OUTPUT_TOKEN
#define CND_APPLIED_ICON_AUDIT_OUTPUT_TOKEN ""
#endif

static const char *const CNDIconAuditOutputPath =
    "/var/tmp/cyanide-applied-icon-audit.plist";

static id CNDSanitizeAuditPropertyList(
    id object,
    NSString *path,
    NSMutableArray<NSDictionary<NSString *, NSString *> *> *replacements,
    NSUInteger depth)
{
    if (!object) return @"<nil>";
    if (depth > 32) {
        if (replacements.count < 64) {
            [replacements addObject:@{
                @"path": path ?: @"<root>",
                @"class": NSStringFromClass([object class]) ?: @"<unknown>",
                @"reason": @"depth-limit",
            }];
        }
        return @"<depth-limit>";
    }
    if ([object isKindOfClass:NSString.class] ||
        [object isKindOfClass:NSNumber.class] ||
        [object isKindOfClass:NSData.class] ||
        [object isKindOfClass:NSDate.class]) {
        return object;
    }
    if ([object isKindOfClass:NSArray.class]) {
        NSMutableArray *values = [NSMutableArray array];
        [(NSArray *)object enumerateObjectsUsingBlock:
            ^(id value, NSUInteger index, BOOL *stop) {
                (void)stop;
                [values addObject:CNDSanitizeAuditPropertyList(
                    value,
                    [NSString stringWithFormat:@"%@[%lu]",
                        path ?: @"<root>", (unsigned long)index],
                    replacements,
                    depth + 1)];
            }];
        return values;
    }
    if ([object isKindOfClass:NSDictionary.class]) {
        NSMutableDictionary *values = [NSMutableDictionary dictionary];
        [(NSDictionary *)object enumerateKeysAndObjectsUsingBlock:
            ^(id key, id value, BOOL *stop) {
                (void)stop;
                NSString *stringKey = [key isKindOfClass:NSString.class]
                    ? key : [key description];
                if (![key isKindOfClass:NSString.class] &&
                    replacements.count < 64) {
                    [replacements addObject:@{
                        @"path": path ?: @"<root>",
                        @"class": NSStringFromClass([key class]) ?:
                            @"<unknown>",
                        @"reason": @"dictionary-key",
                    }];
                }
                NSString *childPath = [NSString stringWithFormat:@"%@.%@",
                    path ?: @"<root>", stringKey ?: @"<nil-key>"];
                values[stringKey ?: @"<nil-key>"] =
                    CNDSanitizeAuditPropertyList(
                        value, childPath, replacements, depth + 1);
            }];
        return values;
    }
    if (replacements.count < 64) {
        [replacements addObject:@{
            @"path": path ?: @"<root>",
            @"class": NSStringFromClass([object class]) ?: @"<unknown>",
            @"reason": @"unsupported-value",
        }];
    }
    return [object description] ?: @"<unsupported>";
}

__attribute__((constructor))
static void CNDRunAppliedIconAudit(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        if (CND_APPLIED_ICON_AUDIT_OUTPUT_TOKEN[0] && consume) {
            (void)consume(CND_APPLIED_ICON_AUDIT_OUTPUT_TOKEN);
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            @autoreleasepool {
                typedef bool (*KRWReadyFunction)(void);
                KRWReadyFunction krwReady = (KRWReadyFunction)dlsym(
                    RTLD_DEFAULT, "kexploit_krw_ready");
                Class remixClass = objc_getClass("CNDSnowBoardRemix");
                SEL selector = sel_registerName("auditAppliedIconState");
                NSDictionary *result = nil;
                if (!krwReady) {
                    result = @{
                        @"ok": @NO,
                        @"stage": @"krw-symbol-resolution",
                        @"message": @"kexploit_krw_ready is unavailable.",
                    };
                } else if (!krwReady()) {
                    result = @{
                        @"ok": @NO,
                        @"stage": @"vm-krw-prerequisite",
                        @"message": @"The vPhone lab support provider could not be activated.",
                    };
                } else if (!remixClass || !class_respondsToSelector(
                               object_getClass(remixClass), selector)) {
                    result = @{
                        @"ok": @NO,
                        @"stage": @"symbol-resolution",
                        @"message": @"CNDSnowBoardRemix auditAppliedIconState is unavailable.",
                    };
                } else {
                    result = ((id (*)(id, SEL))objc_msgSend)(
                        remixClass, selector);
                }
                NSMutableArray *replacements = [NSMutableArray array];
                NSMutableDictionary *serializable =
                    [CNDSanitizeAuditPropertyList(
                        result ?: @{}, @"result", replacements, 0)
                        mutableCopy];
                if (replacements.count > 0) {
                    serializable[@"labSerializationReplacements"] =
                        replacements;
                }
                NSError *error = nil;
                NSData *data = [NSPropertyListSerialization
                    dataWithPropertyList:serializable ?: @{}
                    format:NSPropertyListXMLFormat_v1_0
                    options:0
                    error:&error];
                if (!data) {
                    data = [[NSString stringWithFormat:
                        @"audit serialization failed: %@\n",
                        error.localizedDescription ?: @"unknown"]
                        dataUsingEncoding:NSUTF8StringEncoding];
                }
                int descriptor = open(
                    CNDIconAuditOutputPath,
                    O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
                if (descriptor < 0) return;
                const uint8_t *bytes = data.bytes;
                NSUInteger remaining = data.length;
                while (remaining > 0) {
                    ssize_t written = write(descriptor, bytes, remaining);
                    if (written <= 0) break;
                    bytes += (NSUInteger)written;
                    remaining -= (NSUInteger)written;
                }
                (void)fsync(descriptor);
                (void)close(descriptor);
            }
        });
    }
}
