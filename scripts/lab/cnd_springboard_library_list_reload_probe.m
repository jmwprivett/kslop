#import <Foundation/Foundation.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dispatch/dispatch.h>
#include <stdint.h>

#ifndef CND_LIBRARY_LIST_CONTROLLER_ADDRESS
#define CND_LIBRARY_LIST_CONTROLLER_ADDRESS 0ULL
#endif

#ifndef CND_LIBRARY_LIST_PURGE_CACHE
#define CND_LIBRARY_LIST_PURGE_CACHE 0
#endif

#ifndef CND_LIBRARY_LIST_ACTION
#define CND_LIBRARY_LIST_ACTION 0
#endif

#ifndef CND_LIBRARY_LIST_ICON_ADDRESS
#define CND_LIBRARY_LIST_ICON_ADDRESS 0ULL
#endif

__attribute__((constructor))
static void CNDLibraryListReloadProbeStart(void)
{
    uintptr_t address = (uintptr_t)CND_LIBRARY_LIST_CONTROLLER_ADDRESS;
    if (!address) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        id controller = (__bridge id)(void *)address;
        Class expected = objc_getClass("SBHIconLibraryTableViewController");
        if (!controller || !expected ||
            ![controller isKindOfClass:expected]) {
            return;
        }
        const char *selectorName = CND_LIBRARY_LIST_ACTION == 1
            ? "_reloadAppIcons"
            : (CND_LIBRARY_LIST_ACTION == 2
                ? "_refreshIconIfVisible:"
                : (CND_LIBRARY_LIST_ACTION == 3
                    ? "reloadIconImage"
                    : "_reloadVisibleCells"));
        SEL selector = sel_registerName(selectorName);
        if (CND_LIBRARY_LIST_ACTION != 3 &&
            ![controller respondsToSelector:selector]) return;
#if CND_LIBRARY_LIST_PURGE_CACHE
        SEL cacheSelector = sel_registerName("iconImageCache");
        id cache = [controller respondsToSelector:cacheSelector]
            ? ((id (*)(id, SEL))objc_msgSend)(controller, cacheSelector)
            : nil;
        SEL purgeSelector = sel_registerName("purgeAllCachedImages");
        if (cache && [cache respondsToSelector:purgeSelector]) {
            ((void (*)(id, SEL))objc_msgSend)(cache, purgeSelector);
        }
#endif
        if (CND_LIBRARY_LIST_ACTION == 2 ||
            CND_LIBRARY_LIST_ACTION == 3) {
            uintptr_t iconAddress =
                (uintptr_t)CND_LIBRARY_LIST_ICON_ADDRESS;
            id icon = (__bridge id)(void *)iconAddress;
            Class iconClass = objc_getClass("SBIcon");
            if (!icon || !iconClass || ![icon isKindOfClass:iconClass]) {
                return;
            }
            if (CND_LIBRARY_LIST_ACTION == 3) {
                if (![icon respondsToSelector:selector]) return;
                ((void (*)(id, SEL))objc_msgSend)(icon, selector);
            } else {
                ((void (*)(id, SEL, id))objc_msgSend)(
                    controller, selector, icon);
            }
        } else {
            ((void (*)(id, SEL))objc_msgSend)(controller, selector);
        }
    });
}
