#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>

#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef CND_REFRESH_PROBE_OUTPUT_TOKEN
#define CND_REFRESH_PROBE_OUTPUT_TOKEN ""
#endif

#ifndef CND_REFRESH_PROBE_OUTPUT_PATH
#define CND_REFRESH_PROBE_OUTPUT_PATH \
    "/var/tmp/cyanide-springboard-refresh-probe.log"
#endif

#ifndef CND_REFRESH_PROBE_ACTION
#define CND_REFRESH_PROBE_ACTION "inventory"
#endif

#ifndef CND_REFRESH_PROBE_TARGET_BUNDLE
#define CND_REFRESH_PROBE_TARGET_BUNDLE "com.ebay.iphone"
#endif

static int gCNDRefreshProbeFD = -1;
static bool gCNDRefreshProbeCompletionDeferred = false;
static NSUInteger gCNDRefreshProbeRecipeCompletions = 0U;

static void CNDRefreshProbeLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDRefreshProbeLog(const char *format, ...)
{
    if (gCNDRefreshProbeFD < 0) return;
    char line[8192] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = (size_t)length < sizeof(line)
        ? (size_t)length : sizeof(line) - 1U;
    (void)write(gCNDRefreshProbeFD, line, amount);
}

static bool CNDRefreshProbeRelevantSelector(const char *name)
{
    if (!name) return false;
    static const char *const tokens[] = {
        "cache", "Cache", "icon", "Icon", "reload", "Reload",
        "reset", "Reset", "refresh", "Refresh", "invalidate",
        "Invalidate", "purge", "Purge", "rebuild", "Rebuild",
        "layout", "Layout", "library", "Library", "folder", "Folder",
        "configure", "Configure", "visible", "Visible",
        "lock", "Lock", "unlock", "Unlock", "dismiss", "Dismiss",
        "cover", "Cover", "activate", "Activate", "notification",
        "Notification", "request", "Request", "list", "List",
        "switcher", "Switcher", "title", "Title", "space", "Space",
        "content", "Content", "container", "Container",
    };
    for (size_t index = 0;
         index < sizeof(tokens) / sizeof(tokens[0]); index++) {
        if (strstr(name, tokens[index])) return true;
    }
    return false;
}

static void CNDRefreshProbeDumpMethods(Class cls, bool classMethods)
{
    if (!cls) return;
    Class owner = classMethods ? object_getClass(cls) : cls;
    unsigned count = 0U;
    Method *methods = class_copyMethodList(owner, &count);
    for (unsigned index = 0; methods && index < count; index++) {
        SEL selector = method_getName(methods[index]);
        const char *name = selector ? sel_getName(selector) : NULL;
        if (!CNDRefreshProbeRelevantSelector(name)) continue;
        CNDRefreshProbeLog(
            "[CND_REFRESH] method class=%s kind=%c selector=%s types=%s "
            "imp=%p\n", class_getName(cls), classMethods ? '+' : '-',
            name ?: "-", method_getTypeEncoding(methods[index]) ?: "-",
            method_getImplementation(methods[index]));
    }
    free(methods);
}

static id CNDRefreshProbeNoArgument(id object, const char *selectorName)
{
    if (!object || !selectorName) return nil;
    SEL selector = sel_registerName(selectorName);
    if (![object respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(object, selector);
}

static bool CNDRefreshProbeVoidNoArgument(id object,
                                          const char *selectorName)
{
    if (!object || !selectorName) return false;
    SEL selector = sel_registerName(selectorName);
    if (![object respondsToSelector:selector]) return false;
    CNDRefreshProbeLog(
        "[CND_REFRESH] call begin object=%p class=%s selector=%s\n",
        object, class_getName([object class]), selectorName);
    ((void (*)(id, SEL))objc_msgSend)(object, selector);
    CNDRefreshProbeLog(
        "[CND_REFRESH] call end object=%p class=%s selector=%s\n",
        object, class_getName([object class]), selectorName);
    return true;
}

static bool CNDRefreshProbeVoidBoolean(id object,
                                       const char *selectorName,
                                       BOOL value)
{
    if (!object || !selectorName) return false;
    SEL selector = sel_registerName(selectorName);
    if (![object respondsToSelector:selector]) return false;
    CNDRefreshProbeLog(
        "[CND_REFRESH] call begin object=%p class=%s selector=%s "
        "value=%d\n", object, class_getName([object class]),
        selectorName, value ? 1 : 0);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(object, selector, value);
    CNDRefreshProbeLog(
        "[CND_REFRESH] call end object=%p class=%s selector=%s\n",
        object, class_getName([object class]), selectorName);
    return true;
}

static bool CNDRefreshProbeLayout(id object)
{
    const char *selectorName =
        "layoutIconListsWithAnimationType:forceRelayout:";
    SEL selector = sel_registerName(selectorName);
    if (!object || ![object respondsToSelector:selector]) return false;
    CNDRefreshProbeLog(
        "[CND_REFRESH] call begin object=%p class=%s selector=%s "
        "animation=0 force=1\n", object, class_getName([object class]),
        selectorName);
    ((void (*)(id, SEL, NSInteger, BOOL))objc_msgSend)(
        object, selector, 0, YES);
    CNDRefreshProbeLog(
        "[CND_REFRESH] call end object=%p class=%s selector=%s\n",
        object, class_getName([object class]), selectorName);
    return true;
}

static bool CNDRefreshProbeUnlock(void)
{
    Class cls = objc_getClass("SBLockScreenManager");
    id manager = CNDRefreshProbeNoArgument(cls, "sharedInstance");
    SEL lockedSelector = sel_registerName("isUILocked");
    bool before = manager && [manager respondsToSelector:lockedSelector]
        ? ((BOOL (*)(id, SEL))objc_msgSend)(manager, lockedSelector) : false;
    SEL selector = sel_registerName("unlockUIFromSource:withOptions:");
    if (!manager || ![manager respondsToSelector:selector]) {
        CNDRefreshProbeLog(
            "[CND_REFRESH] unlock unavailable manager=%p/%s before=%d\n",
            manager, manager ? class_getName([manager class]) : "-",
            before ? 1 : 0);
        return false;
    }
    BOOL result = ((BOOL (*)(id, SEL, int, id))objc_msgSend)(
        manager, selector, 0, nil);
    id coverSheet = CNDRefreshProbeNoArgument(
        manager, "coverSheetViewController");
    SEL responseSelector = sel_registerName("respondToUIUnlockFromSource:");
    bool responded = coverSheet &&
        [coverSheet respondsToSelector:responseSelector];
    if (responded) {
        ((void (*)(id, SEL, int))objc_msgSend)(
            coverSheet, responseSelector, 0);
    }
    bool after = [manager respondsToSelector:lockedSelector]
        ? ((BOOL (*)(id, SEL))objc_msgSend)(manager, lockedSelector) : false;
    CNDRefreshProbeLog(
        "[CND_REFRESH] unlock manager=%p/%s before=%d result=%d after=%d\n",
        manager, class_getName([manager class]), before ? 1 : 0,
        result ? 1 : 0, after ? 1 : 0);
    return result || !after;
}

static bool CNDRefreshProbeForceUnlock(void)
{
    Class cls = objc_getClass("SBLockScreenManager");
    id manager = CNDRefreshProbeNoArgument(cls, "sharedInstance");
    SEL lockedSelector = sel_registerName("isUILocked");
    bool before = manager && [manager respondsToSelector:lockedSelector]
        ? ((BOOL (*)(id, SEL))objc_msgSend)(manager, lockedSelector) : false;
    SEL selector = sel_registerName(
        "_finishUIUnlockFromSource:withOptions:");
    if (!manager || ![manager respondsToSelector:selector]) return false;
    BOOL result = ((BOOL (*)(id, SEL, int, id))objc_msgSend)(
        manager, selector, 0, nil);
    id coverSheet = CNDRefreshProbeNoArgument(
        manager, "coverSheetViewController");
    bool prepared = CNDRefreshProbeVoidNoArgument(
        coverSheet, "prepareForUIUnlock");
    SEL finishSelector = sel_registerName("finishUIUnlockFromSource:");
    bool finished = coverSheet &&
        [coverSheet respondsToSelector:finishSelector];
    if (finished) {
        ((void (*)(id, SEL, int))objc_msgSend)(
            coverSheet, finishSelector, 0);
    }
    bool after = [manager respondsToSelector:lockedSelector]
        ? ((BOOL (*)(id, SEL))objc_msgSend)(manager, lockedSelector) : false;
    CNDRefreshProbeLog(
        "[CND_REFRESH] force-unlock manager=%p/%s before=%d result=%d "
        "after=%d cover-sheet=%p/%s prepared=%d finished=%d\n",
        manager, class_getName([manager class]),
        before ? 1 : 0, result ? 1 : 0, after ? 1 : 0,
        coverSheet, coverSheet ? class_getName([coverSheet class]) : "-",
        prepared ? 1 : 0, finished ? 1 : 0);
    return result || !after;
}

static void CNDRefreshProbeLogGetter(id object, const char *selectorName)
{
    SEL selector = sel_registerName(selectorName);
    bool responds = object && [object respondsToSelector:selector];
    id value = responds
        ? ((id (*)(id, SEL))objc_msgSend)(object, selector) : nil;
    CNDRefreshProbeLog(
        "[CND_REFRESH] getter owner=%p/%s selector=%s responds=%d "
        "value=%p/%s\n", object,
        object ? class_getName([object class]) : "-", selectorName,
        responds ? 1 : 0, value,
        value ? class_getName([value class]) : "-");
}

static void CNDRefreshProbeInventory(void)
{
    static const char *const classNames[] = {
        "SBIconController", "SBHIconManager", "SBHIconModel",
        "SBIconModel", "SBHIconImageCache", "SBFolderIconImageCache",
        "SBHLibraryViewController", "SBLibraryViewController",
        "SBHLibraryPodFolderController",
        "SBHLibraryCategoryPodIconListView", "SBRootFolderController",
        "SBMainSwitcherController", "SBSwitcherController",
        "SBSwitcherViewController", "SBFluidSwitcherViewController",
        "SBFluidSwitcherSpaceTitleItemController",
        "SBLockScreenManager", "CSCoverSheetViewController",
        "SBMainWorkspace", "SBLockScreenViewController",
    };
    for (size_t index = 0;
         index < sizeof(classNames) / sizeof(classNames[0]); index++) {
        Class cls = objc_getClass(classNames[index]);
        CNDRefreshProbeLog(
            "[CND_REFRESH] class name=%s loaded=%d object=%p superclass=%s\n",
            classNames[index], cls ? 1 : 0, cls,
            cls && class_getSuperclass(cls)
                ? class_getName(class_getSuperclass(cls)) : "-");
        CNDRefreshProbeDumpMethods(cls, false);
        CNDRefreshProbeDumpMethods(cls, true);
    }
}

static bool CNDRefreshProbeAddObject(id __unsafe_unretained *objects,
                                     NSUInteger *count,
                                     NSUInteger capacity, id object)
{
    if (!objects || !count || !object || *count >= capacity) return false;
    for (NSUInteger index = 0; index < *count; index++) {
        if (objects[index] == object) return false;
    }
    objects[(*count)++] = object;
    return true;
}

static void CNDRefreshProbeDumpNotificationIvars(Class cls)
{
    for (Class cursor = cls; cursor; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0U;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        for (unsigned index = 0; ivars && index < count; index++) {
            const char *name = ivar_getName(ivars[index]);
            const char *type = ivar_getTypeEncoding(ivars[index]);
            if (!CNDRefreshProbeRelevantSelector(name)) continue;
            CNDRefreshProbeLog(
                "[CND_REFRESH] notification-ivar class=%s owner=%s "
                "name=%s type=%s offset=%td\n", class_getName(cls),
                class_getName(cursor), name ?: "-", type ?: "-",
                ivar_getOffset(ivars[index]));
        }
        free(ivars);
    }
}

static void CNDRefreshProbeLogExactMethod(id object,
                                          const char *selectorName)
{
    if (!object || !selectorName) return;
    SEL selector = sel_registerName(selectorName);
    Method method = class_getInstanceMethod([object class], selector);
    CNDRefreshProbeLog(
        "[CND_REFRESH] notification-exact-method object=%p/%s "
        "selector=%s responds=%d types=%s imp=%p\n", object,
        class_getName([object class]), selectorName,
        [object respondsToSelector:selector] ? 1 : 0,
        method ? method_getTypeEncoding(method) : "-",
        method ? method_getImplementation(method) : NULL);
}

static void CNDRefreshProbeCollectNotificationIvars(
    id owner, id __unsafe_unretained *objects, NSUInteger *objectCount,
    NSUInteger capacity)
{
    if (!owner) return;
    for (Class cursor = [owner class]; cursor;
         cursor = class_getSuperclass(cursor)) {
        unsigned count = 0U;
        Ivar *ivars = class_copyIvarList(cursor, &count);
        for (unsigned index = 0; ivars && index < count; index++) {
            const char *name = ivar_getName(ivars[index]);
            const char *type = ivar_getTypeEncoding(ivars[index]);
            if (!name || !type || type[0] != '@' ||
                !CNDRefreshProbeRelevantSelector(name)) {
                continue;
            }
            id value = object_getIvar(owner, ivars[index]);
            CNDRefreshProbeLog(
                "[CND_REFRESH] notification-object-ivar owner=%p/%s "
                "declared=%s name=%s value=%p/%s\n", owner,
                class_getName([owner class]), class_getName(cursor), name,
                value, value ? class_getName([value class]) : "-");
            CNDRefreshProbeAddObject(
                objects, objectCount, capacity, value);
        }
        free(ivars);
    }
}

static void CNDRefreshProbeNotificationInventory(void)
{
    (void)dlopen(
        "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
        "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);
    (void)dlopen(
        "/System/Library/PrivateFrameworks/CoverSheet.framework/CoverSheet",
        RTLD_NOW | RTLD_LOCAL);

    static const char *const classNames[] = {
        "SBLockScreenManager", "SBMainWorkspace",
        "CSCoverSheetViewController", "CSCombinedListViewController",
        "CSNotificationViewController",
        "NCNotificationStructuredListViewController",
        "NCNotificationListViewController", "NCNotificationListView",
        "NCNotificationCombinedSectionList", "NCNotificationGroupList",
        "NCNotificationRootList", "NCBulletinNotificationSource",
        "NCBadgedIconView", "NCNotificationIconRecipe",
        "NCUIMappedImageCache", "BSUIMappedImageCache",
    };
    for (NSUInteger index = 0;
         index < sizeof(classNames) / sizeof(classNames[0]); index++) {
        Class cls = objc_getClass(classNames[index]);
        CNDRefreshProbeLog(
            "[CND_REFRESH] notification-class name=%s loaded=%d object=%p "
            "superclass=%s\n", classNames[index], cls ? 1 : 0, cls,
            cls && class_getSuperclass(cls)
                ? class_getName(class_getSuperclass(cls)) : "-");
        CNDRefreshProbeDumpMethods(cls, false);
        CNDRefreshProbeDumpMethods(cls, true);
        CNDRefreshProbeDumpNotificationIvars(cls);
    }

    Class mappedCacheClass = objc_getClass("NCUIMappedImageCache");
    id mappedCache = CNDRefreshProbeNoArgument(
        mappedCacheClass, "sharedCache");
    static const char *const mappedSelectors[] = {
        "allKeys", "imageForKey:", "setImage:forKey:",
        "removeAllObjects", "removeAllImagesWithCompletion:",
        "releaseRecoverableResources",
    };
    for (NSUInteger index = 0;
         index < sizeof(mappedSelectors) / sizeof(mappedSelectors[0]);
         index++) {
        CNDRefreshProbeLogExactMethod(mappedCache, mappedSelectors[index]);
    }
    id mappedKeys = CNDRefreshProbeNoArgument(mappedCache, "allKeys");
    NSUInteger mappedKeyCount = [mappedKeys respondsToSelector:@selector(count)]
        ? [mappedKeys count] : 0U;
    NSUInteger boundedKeyCount = MIN(mappedKeyCount, 256U);
    NSUInteger matchingKeyCount = 0U;
    NSUInteger loggedMatchingKeyCount = 0U;
    NSString *targetBundle = @CND_REFRESH_PROBE_TARGET_BUNDLE;
    for (NSUInteger index = 0; index < boundedKeyCount; index++) {
        id key = [mappedKeys objectAtIndex:index];
        NSString *description = [key description];
        if (index < 12U) {
            CNDRefreshProbeLog(
                "[CND_REFRESH] notification-mapped-sample index=%lu "
                "key=%s\n", (unsigned long)index,
                description.UTF8String ?: "-");
        }
        if (![description containsString:targetBundle]) continue;
        matchingKeyCount++;
        if (loggedMatchingKeyCount < 8U) {
            CNDRefreshProbeLog(
                "[CND_REFRESH] notification-mapped-key index=%lu "
                "key=%s\n", (unsigned long)index,
                description.UTF8String ?: "-");
            loggedMatchingKeyCount++;
        }
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] notification-mapped-cache object=%p/%s "
        "keys=%p/%s count=%lu inspected=%lu target=%s matches=%lu "
        "truncated=%d\n", mappedCache,
        mappedCache ? class_getName([mappedCache class]) : "-", mappedKeys,
        mappedKeys ? class_getName([mappedKeys class]) : "-",
        (unsigned long)mappedKeyCount, (unsigned long)boundedKeyCount,
        CND_REFRESH_PROBE_TARGET_BUNDLE, (unsigned long)matchingKeyCount,
        mappedKeyCount > boundedKeyCount ? 1 : 0);

    enum { OBJECT_CAP = 64 };
    id __unsafe_unretained objects[OBJECT_CAP] = {0};
    NSUInteger objectCount = 0U;
    Class lockManagerClass = objc_getClass("SBLockScreenManager");
    Class workspaceClass = objc_getClass("SBMainWorkspace");
    CNDRefreshProbeAddObject(
        objects, &objectCount, OBJECT_CAP,
        CNDRefreshProbeNoArgument(lockManagerClass, "sharedInstance"));
    CNDRefreshProbeAddObject(
        objects, &objectCount, OBJECT_CAP,
        CNDRefreshProbeNoArgument(workspaceClass, "sharedInstance"));

    static const char *const getters[] = {
        "coverSheetViewController", "coverSheetWindow",
        "combinedListViewController", "notificationViewController",
        "notificationListViewController",
        "notificationStructuredListViewController",
        "structuredListViewController", "listViewController",
        "contentViewController", "rootViewController", "viewController",
        "notificationList", "combinedList", "rootList", "groupList",
        "listModel", "model", "delegate", "dataSource",
    };
    for (NSUInteger cursor = 0;
         cursor < objectCount && cursor < OBJECT_CAP; cursor++) {
        id owner = objects[cursor];
        CNDRefreshProbeLog(
            "[CND_REFRESH] notification-object index=%lu object=%p class=%s\n",
            (unsigned long)cursor, owner,
            owner ? class_getName([owner class]) : "-");
        CNDRefreshProbeCollectNotificationIvars(
            owner, objects, &objectCount, OBJECT_CAP);
        for (NSUInteger selectorIndex = 0;
             selectorIndex < sizeof(getters) / sizeof(getters[0]);
             selectorIndex++) {
            SEL selector = sel_registerName(getters[selectorIndex]);
            if (!owner || ![owner respondsToSelector:selector]) continue;
            id value = ((id (*)(id, SEL))objc_msgSend)(owner, selector);
            CNDRefreshProbeLog(
                "[CND_REFRESH] notification-getter owner=%p/%s selector=%s "
                "value=%p/%s\n", owner, class_getName([owner class]),
                getters[selectorIndex], value,
                value ? class_getName([value class]) : "-");
            CNDRefreshProbeAddObject(
                objects, &objectCount, OBJECT_CAP, value);
        }
    }
}

static id CNDRefreshProbeObjectIvar(id object, const char *name)
{
    if (!object || !name) return nil;
    Ivar ivar = class_getInstanceVariable([object class], name);
    return ivar ? object_getIvar(object, ivar) : nil;
}

static id CNDRefreshProbeNotificationRoot(void)
{
    id lockManager = CNDRefreshProbeNoArgument(
        objc_getClass("SBLockScreenManager"), "sharedInstance");
    id coverSheet = CNDRefreshProbeObjectIvar(
        lockManager, "_coverSheetViewController");
    if (!coverSheet) {
        coverSheet = CNDRefreshProbeNoArgument(
            lockManager, "coverSheetViewController");
    }
    id dispatcher = CNDRefreshProbeObjectIvar(
        coverSheet, "_notificationDispatcher");
    id destination = CNDRefreshProbeObjectIvar(
        dispatcher, "_listDestination");
    id combined = CNDRefreshProbeObjectIvar(
        destination, "_combinedListViewController");
    if (!combined) {
        combined = CNDRefreshProbeNoArgument(
            destination, "combinedListViewController");
    }
    id structured = CNDRefreshProbeObjectIvar(
        combined, "_structuredListViewController");
    id root = CNDRefreshProbeObjectIvar(structured, "_listModel");
    if (!root) root = CNDRefreshProbeNoArgument(structured, "listModel");
    CNDRefreshProbeLog(
        "[CND_REFRESH] notification-graph lock=%p/%s cover=%p/%s "
        "dispatcher=%p/%s destination=%p/%s combined=%p/%s "
        "structured=%p/%s root=%p/%s\n",
        lockManager, lockManager ? class_getName([lockManager class]) : "-",
        coverSheet, coverSheet ? class_getName([coverSheet class]) : "-",
        dispatcher, dispatcher ? class_getName([dispatcher class]) : "-",
        destination, destination ? class_getName([destination class]) : "-",
        combined, combined ? class_getName([combined class]) : "-",
        structured, structured ? class_getName([structured class]) : "-",
        root, root ? class_getName([root class]) : "-");
    return root;
}

static bool CNDRefreshProbeNotificationCachePurge(void)
{
    (void)dlopen(
        "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
        "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);
    Class cacheClass = objc_getClass("NCUIMappedImageCache");
    id cache = CNDRefreshProbeNoArgument(cacheClass, "sharedCache");
    id beforeKeys = CNDRefreshProbeNoArgument(cache, "allKeys");
    NSUInteger before = [beforeKeys respondsToSelector:@selector(count)]
        ? [beforeKeys count] : NSNotFound;
    CNDRefreshProbeLogExactMethod(cache, "removeAllObjects");
    CNDRefreshProbeLogExactMethod(cache, "allKeys");
    bool purged = CNDRefreshProbeVoidNoArgument(cache, "removeAllObjects");
    /* BSUIMappedImageCache queues removal asynchronously. Its -allKeys
     * implementation uses dispatch_async_and_wait on that same serial queue,
     * making this immediately following read the deterministic FIFO barrier. */
    id afterKeys = CNDRefreshProbeNoArgument(cache, "allKeys");
    NSUInteger after = [afterKeys respondsToSelector:@selector(count)]
        ? [afterKeys count] : NSNotFound;
    CNDRefreshProbeLog(
        "[CND_REFRESH] notification-mapped-purge cache=%p/%s "
        "before=%lu after=%lu fifo-barrier=allKeys purged=%d main=%d\n",
        cache, cache ? class_getName([cache class]) : "-",
        (unsigned long)before, (unsigned long)after, purged ? 1 : 0,
        [NSThread isMainThread] ? 1 : 0);
    return cache && purged && after == 0U;
}

static id CNDRefreshProbeObjectArgument(id object,
                                        const char *selectorName,
                                        id argument)
{
    if (!object || !selectorName) return nil;
    SEL selector = sel_registerName(selectorName);
    if (![object respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL, id))objc_msgSend)(
        object, selector, argument);
}

static bool CNDRefreshProbeNotificationConsumers(void)
{
    (void)dlopen(
        "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
        "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);
    id root = CNDRefreshProbeNotificationRoot();
    NSArray *sections = CNDRefreshProbeNoArgument(
        root, "notificationSections");
    if (![sections isKindOfClass:[NSArray class]]) return false;

    enum {
        SECTION_CAP = 16,
        GROUP_CAP = 128,
        ICON_VIEW_CAP = 128,
    };
    NSUInteger boundedSections = MIN(sections.count, (NSUInteger)SECTION_CAP);
    NSUInteger groupCount = 0U;
    NSUInteger requestCount = 0U;
    NSUInteger cellCount = 0U;
    NSUInteger lookCount = 0U;
    NSUInteger contentCount = 0U;
    NSUInteger badgedCount = 0U;
    id __unsafe_unretained badgedViews[ICON_VIEW_CAP] = {0};
    for (NSUInteger sectionIndex = 0;
         sectionIndex < boundedSections && groupCount < GROUP_CAP;
         sectionIndex++) {
        id section = sections[sectionIndex];
        CNDRefreshProbeLogExactMethod(
            section, "allNotificationGroups");
        CNDRefreshProbeLogExactMethod(section, "notificationGroups");
        NSArray *groups = CNDRefreshProbeNoArgument(
            section, "allNotificationGroups");
        if (![groups isKindOfClass:[NSArray class]]) {
            groups = CNDRefreshProbeNoArgument(
                section, "notificationGroups");
        }
        if (![groups isKindOfClass:[NSArray class]]) continue;
        for (id group in groups) {
            if (groupCount >= GROUP_CAP) break;
            groupCount++;
            if (groupCount == 1U) {
                CNDRefreshProbeLogExactMethod(
                    group, "leadingNotificationRequest");
                CNDRefreshProbeLogExactMethod(
                    group, "allNotificationRequests");
                CNDRefreshProbeLogExactMethod(
                    group, "_currentCellForNotificationRequest:");
            }
            id requests = CNDRefreshProbeNoArgument(
                group, "allNotificationRequests");
            if ([requests respondsToSelector:@selector(count)]) {
                requestCount += [requests count];
            }
            id request = CNDRefreshProbeNoArgument(
                group, "leadingNotificationRequest");
            id cell = CNDRefreshProbeObjectArgument(
                group, "_currentCellForNotificationRequest:", request);
            if (!cell) continue;
            cellCount++;
            id controller = CNDRefreshProbeNoArgument(
                cell, "notificationViewController");
            if (!controller) {
                controller = CNDRefreshProbeNoArgument(
                    cell, "contentViewController");
            }
            id look = CNDRefreshProbeNoArgument(
                controller, "_lookViewIfLoaded");
            if (!look) {
                look = CNDRefreshProbeObjectIvar(controller, "_lookView");
            }
            if (look) lookCount++;
            id content = CNDRefreshProbeNoArgument(
                look, "notificationContentView");
            if (!content) {
                content = CNDRefreshProbeNoArgument(
                    look, "_notificationContentView");
            }
            if (!content) {
                content = CNDRefreshProbeObjectIvar(
                    look, "_notificationContentView");
            }
            if (content) contentCount++;
            id badged = CNDRefreshProbeObjectIvar(
                content, "_badgedIconView");
            if (!badged) continue;
            bool duplicate = false;
            for (NSUInteger index = 0; index < badgedCount; index++) {
                duplicate |= badgedViews[index] == badged;
            }
            if (!duplicate && badgedCount < ICON_VIEW_CAP) {
                badgedViews[badgedCount++] = badged;
            }
            id iconView = CNDRefreshProbeNoArgument(badged, "iconView");
            id image = CNDRefreshProbeNoArgument(iconView, "image");
            CNDRefreshProbeLog(
                "[CND_REFRESH] notification-consumer section=%lu "
                "group=%p/%s request=%p/%s cell=%p/%s controller=%p/%s "
                "look=%p/%s content=%p/%s badged=%p/%s icon-view=%p/%s "
                "image=%p/%s\n", (unsigned long)sectionIndex, group,
                group ? class_getName([group class]) : "-", request,
                request ? class_getName([request class]) : "-", cell,
                cell ? class_getName([cell class]) : "-", controller,
                controller ? class_getName([controller class]) : "-", look,
                look ? class_getName([look class]) : "-", content,
                content ? class_getName([content class]) : "-", badged,
                class_getName([badged class]), iconView,
                iconView ? class_getName([iconView class]) : "-", image,
                image ? class_getName([image class]) : "-");
        }
    }
    Class badgedClass = objc_getClass("NCBadgedIconView");
    CNDRefreshProbeLogExactMethod(
        badgedClass ? (id)[badgedClass alloc] : nil, "_updateVisibleIcons");
    CNDRefreshProbeLog(
        "[CND_REFRESH] notification-consumers sections=%lu/%lu "
        "groups=%lu requests=%lu cells=%lu looks=%lu content=%lu "
        "badged=%lu section-cap=%d group-cap=%d icon-cap=%d "
        "truncated=%d main=%d\n", (unsigned long)boundedSections,
        (unsigned long)sections.count, (unsigned long)groupCount,
        (unsigned long)requestCount, (unsigned long)cellCount,
        (unsigned long)lookCount, (unsigned long)contentCount,
        (unsigned long)badgedCount, SECTION_CAP, GROUP_CAP, ICON_VIEW_CAP,
        sections.count > SECTION_CAP || groupCount >= GROUP_CAP ? 1 : 0,
        [NSThread isMainThread] ? 1 : 0);
    return sections.count <= SECTION_CAP && groupCount < GROUP_CAP;
}

static bool CNDRefreshProbeNotificationSources(void)
{
    (void)dlopen(
        "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
        "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);
    id lockManager = CNDRefreshProbeNoArgument(
        objc_getClass("SBLockScreenManager"), "sharedInstance");
    id coverSheet = CNDRefreshProbeObjectIvar(
        lockManager, "_coverSheetViewController");
    if (!coverSheet) {
        coverSheet = CNDRefreshProbeNoArgument(
            lockManager, "coverSheetViewController");
    }
    id coverDispatcher = CNDRefreshProbeObjectIvar(
        coverSheet, "_notificationDispatcher");
    id dispatcher = CNDRefreshProbeNoArgument(coverDispatcher, "delegate");
    id sourceDelegates = CNDRefreshProbeNoArgument(
        dispatcher, "sourceDelegates");
    id sources = CNDRefreshProbeNoArgument(sourceDelegates, "allObjects");
    NSUInteger sourceCount = [sources respondsToSelector:@selector(count)]
        ? [sources count] : 0U;
    enum { SOURCE_CAP = 16 };
    NSUInteger bounded = MIN(sourceCount, (NSUInteger)SOURCE_CAP);
    NSUInteger bulletinCount = 0U;
    for (NSUInteger index = 0; index < bounded; index++) {
        id source = [sources objectAtIndex:index];
        const char *className = source ? class_getName([source class]) : "-";
        CNDRefreshProbeLog(
            "[CND_REFRESH] notification-source index=%lu object=%p/%s\n",
            (unsigned long)index, source, className);
        if (!source || strcmp(className, "NCBulletinNotificationSource")) {
            continue;
        }
        bulletinCount++;
        CNDRefreshProbeLogExactMethod(source, "_applicationIconChanged:");
        id queue = CNDRefreshProbeObjectIvar(source, "_queue");
        id observer = CNDRefreshProbeObjectIvar(source, "_observer");
        id sourceDispatcher = CNDRefreshProbeObjectIvar(
            source, "_dispatcher");
        CNDRefreshProbeLog(
            "[CND_REFRESH] notification-bulletin-source object=%p/%s "
            "queue=%p/%s observer=%p/%s dispatcher=%p/%s\n", source,
            className, queue, queue ? class_getName([queue class]) : "-",
            observer, observer ? class_getName([observer class]) : "-",
            sourceDispatcher,
            sourceDispatcher ? class_getName([sourceDispatcher class]) : "-");
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] notification-sources cover-dispatcher=%p/%s "
        "dispatcher=%p/%s delegates=%p/%s sources=%p/%s count=%lu "
        "bulletin=%lu cap=%d truncated=%d main=%d\n", coverDispatcher,
        coverDispatcher ? class_getName([coverDispatcher class]) : "-",
        dispatcher, dispatcher ? class_getName([dispatcher class]) : "-",
        sourceDelegates,
        sourceDelegates ? class_getName([sourceDelegates class]) : "-",
        sources, sources ? class_getName([sources class]) : "-",
        (unsigned long)sourceCount, (unsigned long)bulletinCount, SOURCE_CAP,
        sourceCount > SOURCE_CAP ? 1 : 0,
        [NSThread isMainThread] ? 1 : 0);
    return dispatcher && sourceDelegates && sourceCount <= SOURCE_CAP &&
        bulletinCount == 1U;
}

static NSString *CNDRefreshProbeImageHash(UIImage *image)
{
    CGImageRef cgImage = image.CGImage;
    size_t width = cgImage ? CGImageGetWidth(cgImage) : 0U;
    size_t height = cgImage ? CGImageGetHeight(cgImage) : 0U;
    if (!width || !height || width > 4096U || height > 4096U ||
        width > SIZE_MAX / 4U || height > SIZE_MAX / (width * 4U)) {
        return @"-";
    }
    size_t rowBytes = width * 4U;
    NSMutableData *pixels = [NSMutableData dataWithLength:rowBytes * height];
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGContextRef context = colorSpace ? CGBitmapContextCreate(
        pixels.mutableBytes, width, height, 8U, rowBytes, colorSpace,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big) : NULL;
    if (colorSpace) CGColorSpaceRelease(colorSpace);
    if (!context) return @"-";
    CGContextSetBlendMode(context, kCGBlendModeCopy);
    CGContextDrawImage(
        context, CGRectMake(0.0, 0.0, width, height), cgImage);
    CGContextRelease(context);
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(pixels.bytes, (CC_LONG)pixels.length, digest);
    NSMutableString *result = [NSMutableString stringWithCapacity:64U];
    for (size_t index = 0; index < sizeof(digest); index++) {
        [result appendFormat:@"%02x", digest[index]];
    }
    return result;
}

static bool CNDRefreshProbeNotificationRecipe(void)
{
    (void)dlopen(
        "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
        "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);
    Class recipeClass = objc_getClass("NCNotificationIconRecipe");
    SEL makeSelector = sel_registerName("iconRecipeForApplicationIdentifier:");
    if (!recipeClass || ![recipeClass respondsToSelector:makeSelector]) {
        return false;
    }
    NSString *bundle = @CND_REFRESH_PROBE_TARGET_BUNDLE;
    id recipe = ((id (*)(id, SEL, id))objc_msgSend)(
        recipeClass, makeSelector, bundle);
    CNDRefreshProbeLogExactMethod(
        recipe, "imageForPointSize:interfaceStyle:completionOnMain:");
    SEL imageSelector = sel_registerName(
        "imageForPointSize:interfaceStyle:completionOnMain:");
    Method method = class_getInstanceMethod([recipe class], imageSelector);
    if (!recipe || !method ||
        strcmp(method_getTypeEncoding(method), "v40@0:8d16q24@?32")) {
        return false;
    }
    gCNDRefreshProbeCompletionDeferred = true;
    gCNDRefreshProbeRecipeCompletions = 0U;
    for (NSInteger style = 1; style <= 2; style++) {
        NSInteger capturedStyle = style;
        ((void (*)(id, SEL, double, NSInteger, id))objc_msgSend)(
            recipe, imageSelector, 38.0, style, ^(UIImage *image) {
                CGImageRef cgImage = image.CGImage;
                CNDRefreshProbeLog(
                    "[CND_REFRESH] notification-recipe bundle=%s "
                    "point=38 style=%ld image=%p/%s pixels=%zux%zu "
                    "rgba-sha256=%s main=%d\n",
                    CND_REFRESH_PROBE_TARGET_BUNDLE, (long)capturedStyle,
                    image, image ? class_getName([image class]) : "-",
                    cgImage ? CGImageGetWidth(cgImage) : 0U,
                    cgImage ? CGImageGetHeight(cgImage) : 0U,
                    CNDRefreshProbeImageHash(image).UTF8String ?: "-",
                    [NSThread isMainThread] ? 1 : 0);
                gCNDRefreshProbeRecipeCompletions++;
                if (gCNDRefreshProbeRecipeCompletions == 2U) {
                    gCNDRefreshProbeCompletionDeferred = false;
                    CNDRefreshProbeLog(
                        "[CND_REFRESH] PROBE_COMPLETE pid=%d "
                        "action=notification-recipe invoked=1\n", getpid());
                }
            });
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        if (!gCNDRefreshProbeCompletionDeferred) return;
        gCNDRefreshProbeCompletionDeferred = false;
        CNDRefreshProbeLog(
            "[CND_REFRESH] notification-recipe timeout completions=%lu\n",
            (unsigned long)gCNDRefreshProbeRecipeCompletions);
        CNDRefreshProbeLog(
            "[CND_REFRESH] PROBE_COMPLETE pid=%d "
            "action=notification-recipe invoked=0\n", getpid());
    });
    return true;
}

static bool CNDRefreshProbeNotificationReload(void)
{
    (void)dlopen(
        "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
        "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);
    (void)dlopen(
        "/System/Library/PrivateFrameworks/CoverSheet.framework/CoverSheet",
        RTLD_NOW | RTLD_LOCAL);

    id root = CNDRefreshProbeNotificationRoot();

    CNDRefreshProbeLog(
        "[CND_REFRESH] notification-reload root=%p/%s\n",
        root, root ? class_getName([root class]) : "-");
    if (!root) return false;

    NSArray *sections = CNDRefreshProbeNoArgument(
        root, "notificationSections");
    if (![sections isKindOfClass:[NSArray class]]) return false;

    NSUInteger sectionCount = sections.count;
    NSUInteger groupCount = 0U;
    NSUInteger requestCount = 0U;
    NSUInteger reloadedSections = 0U;
    for (id section in sections) {
        NSArray *groups = CNDRefreshProbeNoArgument(
            section, "allNotificationGroups");
        if (![groups isKindOfClass:[NSArray class]]) {
            groups = CNDRefreshProbeNoArgument(
                section, "notificationGroups");
        }
        if (![groups isKindOfClass:[NSArray class]]) continue;
        for (id group in groups) {
            if (!group || groupCount >= 128U) break;
            groupCount++;
            id requests = CNDRefreshProbeNoArgument(
                group, "allNotificationRequests");
            if ([requests respondsToSelector:@selector(count)]) {
                requestCount += [requests count];
            }
        }
        /* This stock section-level method performs its own local iteration
         * over the groups and reloads each leading cell.  Passing YES forces
         * every stack, so the probe requires one Objective-C message per
         * section rather than one RemoteCall operation per row. */
        if (CNDRefreshProbeVoidBoolean(
                section,
                "_reloadLeadingNotificationRequestsForStackedNotificationGroupListsWithForceReloadAllStacks:",
                YES)) {
            reloadedSections++;
        }
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] notification-reload sections=%lu groups=%lu "
        "requests=%lu reloaded-sections=%lu bounded-cap=128\n",
        (unsigned long)sectionCount, (unsigned long)groupCount,
        (unsigned long)requestCount, (unsigned long)reloadedSections);
    return reloadedSections > 0U || groupCount == 0U;
}

static id CNDRefreshProbeIconController(void)
{
    Class cls = objc_getClass("SBIconController");
    return CNDRefreshProbeNoArgument(cls, "sharedInstance");
}

static id CNDRefreshProbeIconManager(id controller)
{
    return CNDRefreshProbeNoArgument(controller, "iconManager");
}

static id CNDRefreshProbeIconModel(id manager)
{
    static const char *const selectors[] = {
        "model", "iconModel", "rootFolderController",
    };
    for (size_t index = 0;
         index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        id value = CNDRefreshProbeNoArgument(manager, selectors[index]);
        if (!value) continue;
        const char *name = class_getName([value class]);
        if (name && (strstr(name, "IconModel") ||
                     [value respondsToSelector:sel_registerName("reloadIcons")])) {
            return value;
        }
        id nested = CNDRefreshProbeNoArgument(value, "model");
        if (nested &&
            [nested respondsToSelector:sel_registerName("reloadIcons")]) {
            return nested;
        }
    }
    return nil;
}

static id CNDRefreshProbeIvarObject(id object, const char *name)
{
    if (!object || !name) return nil;
    Ivar ivar = class_getInstanceVariable([object class], name);
    return ivar ? object_getIvar(object, ivar) : nil;
}

static NSUInteger CNDRefreshProbeCollectionCount(id collection)
{
    SEL selector = sel_registerName("count");
    return collection && [collection respondsToSelector:selector]
        ? ((NSUInteger (*)(id, SEL))objc_msgSend)(collection, selector) : 0U;
}

static Class CNDRefreshProbeMethodOwner(Class cls, SEL selector)
{
    for (Class cursor = cls; cursor; cursor = class_getSuperclass(cursor)) {
        unsigned count = 0U;
        Method *methods = class_copyMethodList(cursor, &count);
        for (unsigned index = 0; methods && index < count; index++) {
            if (method_getName(methods[index]) == selector) {
                free(methods);
                return cursor;
            }
        }
        free(methods);
    }
    return Nil;
}

static void CNDRefreshProbeLogMethod(id object, const char *selectorName)
{
    SEL selector = sel_registerName(selectorName);
    Class cls = object ? [object class] : Nil;
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    Class owner = method ? CNDRefreshProbeMethodOwner(cls, selector) : Nil;
    CNDRefreshProbeLog(
        "[CND_REFRESH] selector object=%p/%s selector=%s exists=%d "
        "owner=%s types=%s main=%d\n",
        object, cls ? class_getName(cls) : "-", selectorName,
        method ? 1 : 0, owner ? class_getName(owner) : "-",
        method ? method_getTypeEncoding(method) : "-",
        [NSThread isMainThread] ? 1 : 0);
}

static NSUInteger CNDRefreshProbeImageCount(id cache)
{
    SEL selector = sel_registerName("numberOfCachedImages");
    return cache && [cache respondsToSelector:selector]
        ? ((NSUInteger (*)(id, SEL))objc_msgSend)(cache, selector) : NSNotFound;
}

static uint64_t CNDRefreshProbeMonotonicNanoseconds(void)
{
    struct timespec value = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0U;
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
        (uint64_t)value.tv_nsec;
}

static id CNDRefreshProbeLibraryTableController(id library,
                                                 bool throughSearch)
{
    if (!library) return nil;
    if (!throughSearch) {
        return CNDRefreshProbeNoArgument(
            library, "iconTableViewController");
    }
    id container = CNDRefreshProbeNoArgument(
        library, "containerViewController");
    return CNDRefreshProbeNoArgument(
        container, "searchResultsController");
}

static bool CNDRefreshProbeLibraryTableRefresh(id manager)
{
    id library = CNDRefreshProbeNoArgument(
        manager, "trailingLibraryViewController");
    if (!library) {
        library = CNDRefreshProbeNoArgument(
            manager, "overlayLibraryViewController");
    }
    id controllers[2] = {
        CNDRefreshProbeLibraryTableController(library, false),
        CNDRefreshProbeLibraryTableController(library, true),
    };
    id purgedCaches[2] = { nil, nil };
    NSUInteger purgedCount = 0U;
    NSUInteger controllerCount = 0U;
    NSUInteger appReloadCount = 0U;
    NSUInteger cellReloadCount = 0U;
    for (NSUInteger index = 0U; index < 2U; index++) {
        id table = controllers[index];
        if (!table || (index == 1U && table == controllers[0])) continue;
        controllerCount++;
        id cache = CNDRefreshProbeNoArgument(table, "iconImageCache");
        bool duplicate = false;
        for (NSUInteger cacheIndex = 0U; cacheIndex < purgedCount;
             cacheIndex++) {
            duplicate |= purgedCaches[cacheIndex] == cache;
        }
        if (cache && !duplicate && purgedCount < 2U &&
            CNDRefreshProbeVoidNoArgument(cache, "purgeAllCachedImages")) {
            purgedCaches[purgedCount++] = cache;
        }
        appReloadCount += CNDRefreshProbeVoidNoArgument(
            table, "_reloadAppIcons") ? 1U : 0U;
        cellReloadCount += CNDRefreshProbeVoidNoArgument(
            table, "_reloadVisibleCells") ? 1U : 0U;
        CNDRefreshProbeLog(
            "[CND_REFRESH] library-table index=%lu table=%p/%s cache=%p "
            "direct=%d search=%d main=%d\n", (unsigned long)index,
            table, class_getName([table class]), cache,
            table == controllers[0] ? 1 : 0,
            table == controllers[1] ? 1 : 0,
            [NSThread isMainThread] ? 1 : 0);
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] library-table summary library=%p controllers=%lu "
        "caches=%lu app-reloads=%lu cell-reloads=%lu cap=2\n",
        library, (unsigned long)controllerCount,
        (unsigned long)purgedCount, (unsigned long)appReloadCount,
        (unsigned long)cellReloadCount);
    return controllerCount > 0U && appReloadCount == controllerCount &&
        cellReloadCount == controllerCount;
}

static bool CNDRefreshProbeLibrarySearchQuery(id manager)
{
    id library = CNDRefreshProbeNoArgument(
        manager, "trailingLibraryViewController");
    if (!library) {
        library = CNDRefreshProbeNoArgument(
            manager, "overlayLibraryViewController");
    }
    id searchController = CNDRefreshProbeNoArgument(
        library, "containerViewController");
    id searchField = CNDRefreshProbeNoArgument(
        searchController, "searchField");
    id searchBar = CNDRefreshProbeNoArgument(
        searchController, "searchBar");
    CNDRefreshProbeLogMethod(searchField, "setText:");
    CNDRefreshProbeLogMethod(searchController, "searchBar:textDidChange:");
    SEL setText = sel_registerName("setText:");
    SEL changed = sel_registerName("searchBar:textDidChange:");
    if (!searchField || !searchBar ||
        ![searchField respondsToSelector:setText] ||
        ![searchController respondsToSelector:changed]) {
        CNDRefreshProbeLog(
            "[CND_REFRESH] library-search-query unavailable library=%p/%s "
            "controller=%p/%s field=%p/%s bar=%p/%s\n",
            library, library ? class_getName([library class]) : "-",
            searchController,
            searchController ? class_getName([searchController class]) : "-",
            searchField, searchField ? class_getName([searchField class]) : "-",
            searchBar, searchBar ? class_getName([searchBar class]) : "-");
        return false;
    }
    NSString *query = @"Files";
    ((void (*)(id, SEL, id))objc_msgSend)(searchField, setText, query);
    ((void (*)(id, SEL, id, id))objc_msgSend)(
        searchController, changed, searchBar, query);
    CNDRefreshProbeLog(
        "[CND_REFRESH] library-search-query controller=%p/%s field=%p/%s "
        "bar=%p/%s query=%s active=%d main=%d\n",
        searchController, class_getName([searchController class]),
        searchField, class_getName([searchField class]), searchBar,
        class_getName([searchBar class]), query.UTF8String,
        [[searchController valueForKey:@"active"] boolValue] ? 1 : 0,
        [NSThread isMainThread] ? 1 : 0);
    return true;
}

static bool CNDRefreshProbeSwitcherTitles(void)
{
    id application = [UIApplication sharedApplication];
    id switcherController = CNDRefreshProbeNoArgument(
        application, "_switcherController");
    id switcherViewController = CNDRefreshProbeNoArgument(
        switcherController, "contentViewController");
    if (!switcherViewController) {
        switcherViewController = CNDRefreshProbeNoArgument(
            switcherController, "switcherViewController");
    }
    id map = CNDRefreshProbeIvarObject(
        switcherViewController, "_appLayoutToTitleItemController");
    id values = CNDRefreshProbeNoArgument(map, "allValues");
    NSUInteger count = CNDRefreshProbeCollectionCount(values);
    const NSUInteger cap = 128U;
    NSUInteger bounded = MIN(count, cap);
    NSUInteger eligible = 0U;
    NSUInteger updated = 0U;
    for (NSUInteger index = 0U; index < bounded; index++) {
        id controller = [values objectAtIndex:index];
        CNDRefreshProbeLogMethod(controller, "_updateDisplayItemIcons");
        CNDRefreshProbeLogMethod(controller, "_performUpdateHandler");
        if (!controller || ![controller respondsToSelector:
                sel_registerName("_updateDisplayItemIcons")] ||
            ![controller respondsToSelector:
                sel_registerName("_performUpdateHandler")]) {
            continue;
        }
        eligible++;
        bool icons = CNDRefreshProbeVoidNoArgument(
            controller, "_updateDisplayItemIcons");
        bool handler = CNDRefreshProbeVoidNoArgument(
            controller, "_performUpdateHandler");
        if (icons && handler) updated++;
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] switcher-titles application=%p/%s controller=%p/%s "
        "view-controller=%p/%s map=%p/%s count=%lu eligible=%lu "
        "updated=%lu truncated=%d cap=%lu main=%d\n", application,
        class_getName([application class]), switcherController,
        switcherController ? class_getName([switcherController class]) : "-",
        switcherViewController,
        switcherViewController
            ? class_getName([switcherViewController class]) : "-",
        map, map ? class_getName([map class]) : "-",
        (unsigned long)count, (unsigned long)eligible,
        (unsigned long)updated, count > cap ? 1 : 0,
        (unsigned long)cap, [NSThread isMainThread] ? 1 : 0);
    return count <= cap && updated == eligible;
}

static void CNDRefreshProbeLogSwitcherRetainedConsumer(
    const char *phase, id appLayout, id consumer)
{
    id titleItems = CNDRefreshProbeNoArgument(consumer, "titleItems");
    id holder = CNDRefreshProbeIvarObject(consumer, "_iconAndLabelFooter");
    if (!holder) holder = CNDRefreshProbeIvarObject(consumer, "_footerView");
    if (!holder) holder = CNDRefreshProbeIvarObject(consumer, "_headerView");
    id itemToImageView = CNDRefreshProbeIvarObject(
        holder, "_itemsToIconImageViews");
    NSUInteger itemCount = MIN(CNDRefreshProbeCollectionCount(titleItems),
                               (NSUInteger)16U);
    CNDRefreshProbeLog(
        "[CND_REFRESH] switcher-retained phase=%s app-layout=%p/%s "
        "consumer=%p/%s title-items=%p/%s count=%lu holder=%p/%s "
        "image-map=%p/%s\n", phase ?: "-", appLayout,
        appLayout ? class_getName([appLayout class]) : "-", consumer,
        consumer ? class_getName([consumer class]) : "-", titleItems,
        titleItems ? class_getName([titleItems class]) : "-",
        (unsigned long)itemCount, holder,
        holder ? class_getName([holder class]) : "-", itemToImageView,
        itemToImageView ? class_getName([itemToImageView class]) : "-");
    for (NSUInteger index = 0U; index < itemCount; index++) {
        id item = [titleItems objectAtIndex:index];
        id displayItem = CNDRefreshProbeNoArgument(item, "displayItem");
        id imageContainer = [itemToImageView respondsToSelector:
                @selector(objectForKey:)]
            ? [itemToImageView objectForKey:displayItem] : nil;
        UIImage *image = CNDRefreshProbeNoArgument(imageContainer, "image");
        id customImageView = CNDRefreshProbeNoArgument(
            imageContainer, "customImageView");
        CGImageRef imageRef = image.CGImage;
        CNDRefreshProbeLog(
            "[CND_REFRESH] switcher-retained-image phase=%s index=%lu "
            "item=%p/%s display-item=%p/%s image-container=%p/%s "
            "image=%p pixels=%zux%zu rgba-sha256=%s custom=%p/%s\n",
            phase ?: "-", (unsigned long)index, item,
            item ? class_getName([item class]) : "-", displayItem,
            displayItem ? class_getName([displayItem class]) : "-",
            imageContainer,
            imageContainer ? class_getName([imageContainer class]) : "-",
            image, imageRef ? CGImageGetWidth(imageRef) : 0U,
            imageRef ? CGImageGetHeight(imageRef) : 0U,
            CNDRefreshProbeImageHash(image).UTF8String ?: "-",
            customImageView,
            customImageView ? class_getName([customImageView class]) : "-");
    }
}

static bool CNDRefreshProbeSwitcherRetainedConsumers(bool repaint)
{
    enum {
        TITLE_CAP = 128,
        CONSUMER_MAP_CAP = 3,
        CONSUMER_CAP = TITLE_CAP * CONSUMER_MAP_CAP,
    };
    id application = [UIApplication sharedApplication];
    id switcherController = CNDRefreshProbeNoArgument(
        application, "_switcherController");
    id switcherViewController = CNDRefreshProbeNoArgument(
        switcherController, "contentViewController");
    id titleMap = CNDRefreshProbeIvarObject(
        switcherViewController, "_appLayoutToTitleItemController");
    NSArray *keys = [titleMap respondsToSelector:@selector(allKeys)]
        ? [titleMap allKeys] : @[];
    id __unsafe_unretained controllers[TITLE_CAP] = { nil };
    id __unsafe_unretained controllerKeys[TITLE_CAP] = { nil };
    id __unsafe_unretained consumers[CONSUMER_CAP] = { nil };
    id __unsafe_unretained consumerKeys[CONSUMER_CAP] = { nil };
    NSUInteger controllerCount = 0U;
    NSUInteger consumerCount = 0U;
    id maps[CONSUMER_MAP_CAP] = {
        CNDRefreshProbeIvarObject(
            switcherViewController, "_visibleItemContainers"),
        CNDRefreshProbeIvarObject(
            switcherViewController, "_visibleOverlayAccessoryViews"),
        CNDRefreshProbeIvarObject(
            switcherViewController, "_visibleUnderlayAccessoryViews"),
    };
    NSUInteger boundedKeyCount = MIN(keys.count, (NSUInteger)TITLE_CAP);
    for (NSUInteger index = 0U; index < boundedKeyCount; index++) {
        id key = keys[index];
        id controller = [titleMap respondsToSelector:@selector(objectForKey:)]
            ? [titleMap objectForKey:key] : nil;
        CNDRefreshProbeLogMethod(controller, "_updateDisplayItemIcons");
        CNDRefreshProbeLogMethod(controller, "_performUpdateHandler");
        if (!controller || ![controller respondsToSelector:
                sel_registerName("_updateDisplayItemIcons")] ||
            ![controller respondsToSelector:
                sel_registerName("_performUpdateHandler")]) continue;
        controllers[controllerCount] = controller;
        controllerKeys[controllerCount++] = key;
        for (NSUInteger mapIndex = 0U;
             mapIndex < CONSUMER_MAP_CAP; mapIndex++) {
            id map = maps[mapIndex];
            id consumer = [map respondsToSelector:@selector(objectForKey:)]
                ? [map objectForKey:key] : nil;
            if (!consumer) continue;
            NSUInteger before = consumerCount;
            CNDRefreshProbeAddObject(
                consumers, &consumerCount, CONSUMER_CAP, consumer);
            if (consumerCount > before) {
                consumerKeys[before] = key;
                CNDRefreshProbeLogMethod(
                    consumer, "setTitleItems:animated:");
                CNDRefreshProbeLogSwitcherRetainedConsumer(
                    "before", key, consumer);
            }
        }
    }

    NSUInteger updatedIcons = 0U;
    NSUInteger cleared = 0U;
    NSUInteger rebuilt = 0U;
    if (repaint) {
        for (NSUInteger index = 0U; index < controllerCount; index++) {
            if (CNDRefreshProbeVoidNoArgument(
                    controllers[index], "_updateDisplayItemIcons")) {
                updatedIcons++;
            }
        }
        SEL setter = sel_registerName("setTitleItems:animated:");
        for (NSUInteger index = 0U; index < consumerCount; index++) {
            id consumer = consumers[index];
            Method method = class_getInstanceMethod(
                [consumer class], setter);
            const char *types = method ? method_getTypeEncoding(method) : NULL;
            if (!method || !types || strcmp(types, "v28@0:8@16B24") != 0) {
                continue;
            }
            ((void (*)(id, SEL, id, BOOL))objc_msgSend)(
                consumer, setter, nil, NO);
            cleared++;
        }
        for (NSUInteger index = 0U; index < controllerCount; index++) {
            if (CNDRefreshProbeVoidNoArgument(
                    controllers[index], "_performUpdateHandler")) {
                rebuilt++;
            }
        }
        for (NSUInteger index = 0U; index < consumerCount; index++) {
            CNDRefreshProbeLogSwitcherRetainedConsumer(
                "after", consumerKeys[index], consumers[index]);
        }
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] switcher-retained-summary repaint=%d title-map=%p/%s "
        "keys=%lu controllers=%lu visible-item-map=%p/%s overlay-map=%p/%s "
        "underlay-map=%p/%s consumers=%lu icon-updates=%lu cleared=%lu "
        "rebuilt=%lu truncated=%d main=%d\n", repaint ? 1 : 0, titleMap,
        titleMap ? class_getName([titleMap class]) : "-",
        (unsigned long)keys.count, (unsigned long)controllerCount, maps[0],
        maps[0] ? class_getName([maps[0] class]) : "-", maps[1],
        maps[1] ? class_getName([maps[1] class]) : "-", maps[2],
        maps[2] ? class_getName([maps[2] class]) : "-",
        (unsigned long)consumerCount, (unsigned long)updatedIcons,
        (unsigned long)cleared, (unsigned long)rebuilt,
        keys.count > TITLE_CAP ? 1 : 0,
        [NSThread isMainThread] ? 1 : 0);
    return keys.count <= TITLE_CAP &&
        (!repaint || (updatedIcons == controllerCount &&
                      cleared == consumerCount &&
                      rebuilt == controllerCount));
}

static bool CNDRefreshProbeSwitcherInventory(void)
{
    enum { OBJECT_CAP = 48 };
    id __unsafe_unretained objects[OBJECT_CAP] = { nil };
    NSUInteger count = 0U;
    id application = [UIApplication sharedApplication];
    id switcherController = CNDRefreshProbeNoArgument(
        application, "_switcherController");
    id switcherViewController = CNDRefreshProbeNoArgument(
        switcherController, "switcherViewController");
    CNDRefreshProbeAddObject(objects, &count, OBJECT_CAP, application);
    CNDRefreshProbeAddObject(
        objects, &count, OBJECT_CAP, switcherController);
    CNDRefreshProbeAddObject(
        objects, &count, OBJECT_CAP, switcherViewController);
    for (NSUInteger index = 0U; index < count && index < OBJECT_CAP;
         index++) {
        id object = objects[index];
        Class cls = [object class];
        CNDRefreshProbeLog(
            "[CND_REFRESH] switcher-object index=%lu object=%p/%s\n",
            (unsigned long)index, object, class_getName(cls));
        CNDRefreshProbeDumpMethods(cls, false);
        CNDRefreshProbeCollectNotificationIvars(
            object, objects, &count, OBJECT_CAP);
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] switcher-inventory application=%p controller=%p "
        "view-controller=%p objects=%lu truncated=%d cap=%d main=%d\n",
        application, switcherController, switcherViewController,
        (unsigned long)count, count >= OBJECT_CAP ? 1 : 0, OBJECT_CAP,
        [NSThread isMainThread] ? 1 : 0);
    return switcherController && switcherViewController;
}

static void CNDRefreshProbeLogCacheState(const char *phase,
                                         const char *name, id cache)
{
    CNDRefreshProbeLog(
        "[CND_REFRESH] cache-state phase=%s name=%s pointer=%p/%s "
        "images=%lu\n", phase, name, cache,
        cache ? class_getName([cache class]) : "-",
        (unsigned long)CNDRefreshProbeImageCount(cache));
}

static bool CNDRefreshProbeCacheResetInventory(id controller, id manager)
{
    if (!controller || !manager || ![NSThread isMainThread]) return false;
    (void)dlopen(
        "/System/Library/PrivateFrameworks/UserNotificationsUIKit.framework/"
        "UserNotificationsUIKit", RTLD_NOW | RTLD_LOCAL);

    id managerRawBefore = CNDRefreshProbeIvarObject(
        manager, "_iconImageCache");
    id managerCacheBefore = CNDRefreshProbeNoArgument(
        manager, "iconImageCache");
    id folderBefore = CNDRefreshProbeNoArgument(
        manager, "folderIconImageCache");
    id folderInnerBefore = CNDRefreshProbeNoArgument(
        folderBefore, "iconImageCache");
    id notificationBefore = CNDRefreshProbeNoArgument(
        controller, "notificationIconImageCache");
    id notificationMappedClass = objc_getClass("NCUIMappedImageCache");
    id notificationMappedBefore = CNDRefreshProbeNoArgument(
        notificationMappedClass, "sharedCache");
    id tableBefore = CNDRefreshProbeNoArgument(
        controller, "tableUIIconImageCache");
    id switcherBefore = CNDRefreshProbeNoArgument(
        controller, "appSwitcherHeaderIconImageCache");
    id library = CNDRefreshProbeNoArgument(
        manager, "trailingLibraryViewController");
    if (!library) {
        library = CNDRefreshProbeNoArgument(
            manager, "overlayLibraryViewController");
    }
    id libraryBefore = CNDRefreshProbeNoArgument(
        library, "iconImageCache");
    id pod = CNDRefreshProbeNoArgument(library, "folderController");
    id podBefore = CNDRefreshProbeNoArgument(pod, "iconImageCache");
    id directTable = CNDRefreshProbeLibraryTableController(library, false);
    id searchTable = CNDRefreshProbeLibraryTableController(library, true);
    id directTableBefore = CNDRefreshProbeNoArgument(
        directTable, "iconImageCache");
    id searchTableBefore = CNDRefreshProbeNoArgument(
        searchTable, "iconImageCache");

    CNDRefreshProbeLogMethod(manager, "resetAllIconImageCaches");
    CNDRefreshProbeLogMethod(manager, "iconImageCache");
    CNDRefreshProbeLogMethod(manager, "folderIconImageCache");
    CNDRefreshProbeLogMethod(folderBefore, "iconImageCache");
    CNDRefreshProbeLogMethod(folderBefore, "rebuildAllCachedFolderImages");
    CNDRefreshProbeLogMethod(managerCacheBefore, "purgeAllCachedImages");
    CNDRefreshProbeLogMethod(manager, "relayout");
    CNDRefreshProbeLogMethod(pod, "_reloadAppIcons");
    CNDRefreshProbeLogMethod(library, "_enqueueAppLibraryUpdate");
    CNDRefreshProbeLogMethod(directTable, "_reloadAppIcons");
    CNDRefreshProbeLogMethod(directTable, "_reloadVisibleCells");

    CNDRefreshProbeLog(
        "[CND_REFRESH] reset-graph phase=before manager-raw=%p "
        "manager-getter=%p folder=%p folder-inner=%p notification=%p "
        "notification-mapped=%p table=%p switcher=%p library=%p "
        "library-cache=%p pod=%p "
        "pod-cache=%p direct-table=%p direct-table-cache=%p "
        "search-table=%p search-table-cache=%p main=%d\n",
        managerRawBefore, managerCacheBefore, folderBefore,
        folderInnerBefore, notificationBefore, notificationMappedBefore,
        tableBefore, switcherBefore, library, libraryBefore, pod, podBefore,
        directTable,
        directTableBefore, searchTable, searchTableBefore,
        [NSThread isMainThread] ? 1 : 0);
    CNDRefreshProbeLogCacheState("before", "manager", managerCacheBefore);
    CNDRefreshProbeLogCacheState("before", "folder-inner", folderInnerBefore);
    CNDRefreshProbeLogCacheState("before", "notification", notificationBefore);
    CNDRefreshProbeLogCacheState("before", "table", tableBefore);
    CNDRefreshProbeLogCacheState("before", "switcher", switcherBefore);
    CNDRefreshProbeLogCacheState("before", "library", libraryBefore);
    CNDRefreshProbeLogCacheState("before", "pod", podBefore);
    CNDRefreshProbeLogCacheState(
        "before", "direct-table", directTableBefore);
    CNDRefreshProbeLogCacheState(
        "before", "search-table", searchTableBefore);

    uint64_t start = CNDRefreshProbeMonotonicNanoseconds();
    bool invoked = CNDRefreshProbeVoidNoArgument(
        manager, "resetAllIconImageCaches");
    uint64_t end = CNDRefreshProbeMonotonicNanoseconds();

    id managerRawAfterReset = CNDRefreshProbeIvarObject(
        manager, "_iconImageCache");
    id managerCacheAfter = CNDRefreshProbeNoArgument(
        manager, "iconImageCache");
    id managerRawAfterGetter = CNDRefreshProbeIvarObject(
        manager, "_iconImageCache");
    id folderAfter = CNDRefreshProbeNoArgument(
        manager, "folderIconImageCache");
    id folderInnerAfter = CNDRefreshProbeNoArgument(
        folderAfter, "iconImageCache");
    id notificationAfter = CNDRefreshProbeNoArgument(
        controller, "notificationIconImageCache");
    id notificationMappedAfter = CNDRefreshProbeNoArgument(
        notificationMappedClass, "sharedCache");
    id tableAfter = CNDRefreshProbeNoArgument(
        controller, "tableUIIconImageCache");
    id switcherAfter = CNDRefreshProbeNoArgument(
        controller, "appSwitcherHeaderIconImageCache");
    id libraryAfter = CNDRefreshProbeNoArgument(
        library, "iconImageCache");
    id podAfter = CNDRefreshProbeNoArgument(pod, "iconImageCache");
    id directTableAfter = CNDRefreshProbeNoArgument(
        directTable, "iconImageCache");
    id searchTableAfter = CNDRefreshProbeNoArgument(
        searchTable, "iconImageCache");

    CNDRefreshProbeLog(
        "[CND_REFRESH] reset-call invoked=%d duration-ns=%llu "
        "raw-after-reset=%p raw-after-getter=%p main=%d\n",
        invoked ? 1 : 0, (unsigned long long)(end - start),
        managerRawAfterReset, managerRawAfterGetter,
        [NSThread isMainThread] ? 1 : 0);
    CNDRefreshProbeLog(
        "[CND_REFRESH] reset-graph phase=after manager-getter=%p "
        "folder=%p folder-inner=%p notification=%p "
        "notification-mapped=%p table=%p switcher=%p "
        "library-cache=%p pod-cache=%p direct-table-cache=%p "
        "search-table-cache=%p changed-manager=%d changed-folder=%d "
        "changed-folder-inner=%d changed-notification=%d "
        "changed-notification-mapped=%d changed-table=%d "
        "changed-switcher=%d changed-library=%d changed-pod=%d "
        "changed-direct-table=%d changed-search-table=%d\n",
        managerCacheAfter, folderAfter, folderInnerAfter, notificationAfter,
        notificationMappedAfter, tableAfter, switcherAfter, libraryAfter,
        podAfter, directTableAfter, searchTableAfter,
        managerCacheBefore != managerCacheAfter,
        folderBefore != folderAfter, folderInnerBefore != folderInnerAfter,
        notificationBefore != notificationAfter,
        notificationMappedBefore != notificationMappedAfter,
        tableBefore != tableAfter,
        switcherBefore != switcherAfter, libraryBefore != libraryAfter,
        podBefore != podAfter, directTableBefore != directTableAfter,
        searchTableBefore != searchTableAfter);
    CNDRefreshProbeLogCacheState(
        "after-old", "manager", managerCacheBefore);
    CNDRefreshProbeLogCacheState("after", "manager", managerCacheAfter);
    CNDRefreshProbeLogCacheState("after", "folder-inner", folderInnerAfter);
    CNDRefreshProbeLogCacheState("after", "notification", notificationAfter);
    CNDRefreshProbeLogCacheState("after", "table", tableAfter);
    CNDRefreshProbeLogCacheState("after", "switcher", switcherAfter);
    CNDRefreshProbeLogCacheState("after", "library", libraryAfter);
    CNDRefreshProbeLogCacheState("after", "pod", podAfter);
    CNDRefreshProbeLogCacheState(
        "after", "direct-table", directTableAfter);
    CNDRefreshProbeLogCacheState(
        "after", "search-table", searchTableAfter);
    return invoked && managerRawAfterReset == nil &&
        managerCacheBefore != managerCacheAfter &&
        managerCacheAfter == managerRawAfterGetter;
}

typedef struct {
    CGSize size;
    CGFloat scale;
    CGFloat continuousCornerRadius;
} CNDRefreshProbeIconImageInfo;

static CNDRefreshProbeIconImageInfo CNDRefreshProbeLayerImageInfo(id view)
{
    CNDRefreshProbeIconImageInfo info = {0};
    SEL selector = sel_registerName("iconImageInfo");
    if (view && [view respondsToSelector:selector]) {
        info = ((CNDRefreshProbeIconImageInfo (*)(id, SEL))objc_msgSend)(
            view, selector);
    }
    return info;
}

static bool CNDRefreshProbeTargetIconReload(id manager, id model,
                                            bool refreshVisibleView,
                                            bool refreshImageCache)
{
    SEL lookup = sel_registerName("applicationIconForBundleIdentifier:");
    if (!model || ![model respondsToSelector:lookup]) {
        CNDRefreshProbeLog(
            "[CND_REFRESH] target lookup unavailable model=%p/%s\n",
            model, model ? class_getName([model class]) : "-");
        return false;
    }

    NSString *bundleIdentifier = @(CND_REFRESH_PROBE_TARGET_BUNDLE);
    id icon = ((id (*)(id, SEL, id))objc_msgSend)(
        model, lookup, bundleIdentifier);
    id leafSet = CNDRefreshProbeNoArgument(
        model, "leafIconsUniquedByApplicationBundleIdentifier");
    id leafIcons = CNDRefreshProbeNoArgument(leafSet, "allObjects");
    id leafMatch = nil;
    for (id candidate in leafIcons) {
        id candidateBundle = CNDRefreshProbeNoArgument(
            candidate, "applicationBundleID");
        if ([candidateBundle isEqual:bundleIdentifier]) {
            leafMatch = candidate;
            break;
        }
    }
    id observers = CNDRefreshProbeIvarObject(icon, "_observers");
    id layerViews = CNDRefreshProbeIvarObject(icon, "_iconLayerViews");
    SEL generationSelector = sel_registerName("imageGeneration");
    NSUInteger before = icon && [icon respondsToSelector:generationSelector]
        ? ((NSUInteger (*)(id, SEL))objc_msgSend)(icon, generationSelector)
        : NSNotFound;
    CNDRefreshProbeLog(
        "[CND_REFRESH] target icon=%p/%s bundle=%s generation=%lu "
        "observers=%p/%s count=%lu layer-views=%p/%s count=%lu\n",
        icon, icon ? class_getName([icon class]) : "-",
        bundleIdentifier.UTF8String, (unsigned long)before, observers,
        observers ? class_getName([observers class]) : "-",
        (unsigned long)CNDRefreshProbeCollectionCount(observers), layerViews,
        layerViews ? class_getName([layerViews class]) : "-",
        (unsigned long)CNDRefreshProbeCollectionCount(layerViews));
    CNDRefreshProbeLog(
        "[CND_REFRESH] target identity lookup=%p leaf-match=%p same=%d "
        "leaf-set=%p/%s count=%lu leaf-array=%p/%s count=%lu\n",
        icon, leafMatch, icon == leafMatch ? 1 : 0, leafSet,
        leafSet ? class_getName([leafSet class]) : "-",
        (unsigned long)CNDRefreshProbeCollectionCount(leafSet), leafIcons,
        leafIcons ? class_getName([leafIcons class]) : "-",
        (unsigned long)CNDRefreshProbeCollectionCount(leafIcons));

    id rootController = CNDRefreshProbeNoArgument(
        manager, "rootFolderController");
    SEL displayedLookup = sel_registerName("displayedIconViewForIcon:");
    id displayedView = rootController &&
        [rootController respondsToSelector:displayedLookup]
        ? ((id (*)(id, SEL, id))objc_msgSend)(
            rootController, displayedLookup, icon)
        : nil;
    id displayedIcon = CNDRefreshProbeNoArgument(displayedView, "icon");
    id displayedImageView = CNDRefreshProbeNoArgument(
        displayedView, "_iconImageView");
    CNDRefreshProbeLog(
        "[CND_REFRESH] target displayed root=%p/%s view=%p/%s "
        "view-icon=%p/%s same=%d image-view=%p/%s\n",
        rootController,
        rootController ? class_getName([rootController class]) : "-",
        displayedView,
        displayedView ? class_getName([displayedView class]) : "-",
        displayedIcon,
        displayedIcon ? class_getName([displayedIcon class]) : "-",
        displayedIcon == icon ? 1 : 0,
        displayedImageView,
        displayedImageView ? class_getName([displayedImageView class]) : "-");

    NSArray *attachedViews = CNDRefreshProbeNoArgument(
        layerViews, "allObjects");
    NSUInteger index = 0U;
    for (id view in attachedViews) {
        id contentLayer = CNDRefreshProbeNoArgument(view, "iconContentLayer");
        CNDRefreshProbeIconImageInfo info =
            CNDRefreshProbeLayerImageInfo(view);
        CNDRefreshProbeLog(
            "[CND_REFRESH] target layer-view index=%lu object=%p/%s "
            "appearance=%p image-info=%.3fx%.3f@%.3f radius=%.3f "
            "content-layer=%p/%s\n", (unsigned long)index++,
            view, class_getName([view class]),
            CNDRefreshProbeNoArgument(view, "iconImageAppearance"),
            info.size.width, info.size.height, info.scale,
            info.continuousCornerRadius, contentLayer,
            contentLayer ? class_getName([contentLayer class]) : "-");
    }

    bool invoked = CNDRefreshProbeVoidNoArgument(icon, "reloadIconImage");
    NSUInteger after = icon && [icon respondsToSelector:generationSelector]
        ? ((NSUInteger (*)(id, SEL))objc_msgSend)(icon, generationSelector)
        : NSNotFound;
    CNDRefreshProbeLog(
        "[CND_REFRESH] target reload invoked=%d generation=%lu->%lu "
        "observers=%lu layer-views=%lu\n", invoked ? 1 : 0,
        (unsigned long)before, (unsigned long)after,
        (unsigned long)CNDRefreshProbeCollectionCount(observers),
        (unsigned long)CNDRefreshProbeCollectionCount(layerViews));

    bool cacheRefreshInvoked = false;
    if (refreshImageCache) {
        id imageCache = CNDRefreshProbeNoArgument(manager, "iconImageCache");
        SEL update = sel_registerName("updateImageForIcon:");
        if (imageCache && [imageCache respondsToSelector:update]) {
            ((void (*)(id, SEL, id))objc_msgSend)(imageCache, update, icon);
            cacheRefreshInvoked = true;
        }
        CNDRefreshProbeLog(
            "[CND_REFRESH] target cache-refresh invoked=%d "
            "cache=%p/%s icon=%p\n",
            cacheRefreshInvoked ? 1 : 0, imageCache,
            imageCache ? class_getName([imageCache class]) : "-", icon);
    }

    bool visibleRefreshInvoked = false;
    if (refreshVisibleView && displayedView) {
        visibleRefreshInvoked = CNDRefreshProbeVoidBoolean(
            displayedView, "_updateIconImageViewAnimated:", NO);
        CNDRefreshProbeLog(
            "[CND_REFRESH] target visible-refresh invoked=%d "
            "view=%p image-view=%p\n",
            visibleRefreshInvoked ? 1 : 0, displayedView,
            displayedImageView);
    }
    return invoked && (!refreshVisibleView || !displayedView ||
                       visibleRefreshInvoked) &&
           (!refreshImageCache || cacheRefreshInvoked);
}

static NSString *CNDRefreshProbeBundleForIcon(id icon)
{
    static const char *const selectors[] = {
        "applicationBundleID",
        "applicationBundleIdentifier",
        "bundleIdentifier",
    };
    for (size_t index = 0;
         icon && index < sizeof(selectors) / sizeof(selectors[0]); index++) {
        id value = CNDRefreshProbeNoArgument(icon, selectors[index]);
        if ([value isKindOfClass:NSString.class] && [value length] > 0U) {
            return value;
        }
    }
    return nil;
}

static NSArray *CNDRefreshProbeCollectionObjects(id collection)
{
    if (!collection) return @[];
    if ([collection isKindOfClass:NSArray.class]) return collection;
    id objects = CNDRefreshProbeNoArgument(collection, "allObjects");
    if ([objects isKindOfClass:NSArray.class]) return objects;
    objects = CNDRefreshProbeNoArgument(collection, "allValues");
    return [objects isKindOfClass:NSArray.class] ? objects : @[];
}

static void CNDRefreshProbeLogIconConsumer(const char *role, id icon,
                                           id managerCache,
                                           id rootController)
{
    if (!icon) return;
    id displayedView = nil;
    SEL displayedSelector = sel_registerName("displayedIconViewForIcon:");
    if (rootController &&
        [rootController respondsToSelector:displayedSelector]) {
        displayedView = ((id (*)(id, SEL, id))objc_msgSend)(
            rootController, displayedSelector, icon);
    }
    id imageView = CNDRefreshProbeNoArgument(
        displayedView, "_iconImageView");
    if (!imageView) {
        imageView = CNDRefreshProbeIvarObject(
            displayedView, "_iconImageView");
    }
    id viewIcon = CNDRefreshProbeNoArgument(imageView, "icon");
    id viewCache = CNDRefreshProbeNoArgument(imageView, "iconImageCache");
    UIImage *displayedImage = CNDRefreshProbeNoArgument(
        imageView, "displayedImage");
    id observers = CNDRefreshProbeIvarObject(icon, "_observers");
    id layerViews = CNDRefreshProbeIvarObject(icon, "_iconLayerViews");
    NSUInteger generation = [icon respondsToSelector:
            sel_registerName("imageGeneration")]
        ? ((NSUInteger (*)(id, SEL))objc_msgSend)(
            icon, sel_registerName("imageGeneration"))
        : NSNotFound;
    CGImageRef imageRef = displayedImage.CGImage;
    CNDRefreshProbeLog(
        "[CND_REFRESH] target-consumer role=%s icon=%p/%s bundle=%s "
        "generation=%lu observers=%lu layer-views=%lu home-view=%p/%s "
        "image-view=%p/%s view-icon=%p same-icon=%d cache=%p/%s "
        "manager-cache=%p cache-current=%d image=%p pixels=%zux%zu "
        "rgba-sha256=%s\n",
        role ?: "-", icon, class_getName([icon class]),
        CNDRefreshProbeBundleForIcon(icon).UTF8String ?: "-",
        (unsigned long)generation,
        (unsigned long)CNDRefreshProbeCollectionCount(observers),
        (unsigned long)CNDRefreshProbeCollectionCount(layerViews),
        displayedView,
        displayedView ? class_getName([displayedView class]) : "-",
        imageView, imageView ? class_getName([imageView class]) : "-",
        viewIcon, viewIcon == icon ? 1 : 0,
        viewCache, viewCache ? class_getName([viewCache class]) : "-",
        managerCache, viewCache == managerCache ? 1 : 0,
        displayedImage,
        imageRef ? CGImageGetWidth(imageRef) : 0U,
        imageRef ? CGImageGetHeight(imageRef) : 0U,
        CNDRefreshProbeImageHash(displayedImage).UTF8String ?: "-");

    NSArray *observerObjects = CNDRefreshProbeCollectionObjects(observers);
    NSUInteger observerCount = MIN(observerObjects.count, 64U);
    for (NSUInteger index = 0U; index < observerCount; index++) {
        id observer = observerObjects[index];
        id observerIcon = CNDRefreshProbeNoArgument(observer, "icon");
        id observerCache = CNDRefreshProbeNoArgument(
            observer, "iconImageCache");
        CNDRefreshProbeLog(
            "[CND_REFRESH] target-observer role=%s index=%lu "
            "object=%p/%s icon=%p same-icon=%d cache=%p/%s "
            "cache-current=%d\n", role ?: "-", (unsigned long)index,
            observer, observer ? class_getName([observer class]) : "-",
            observerIcon, observerIcon == icon ? 1 : 0,
            observerCache,
            observerCache ? class_getName([observerCache class]) : "-",
            observerCache == managerCache ? 1 : 0);
    }
}

static bool CNDRefreshProbeTargetConsumers(id manager, id model)
{
    NSString *target = @CND_REFRESH_PROBE_TARGET_BUNDLE;
    SEL lookup = sel_registerName("applicationIconForBundleIdentifier:");
    id canonical = model && [model respondsToSelector:lookup]
        ? ((id (*)(id, SEL, id))objc_msgSend)(model, lookup, target) : nil;
    id managerCache = CNDRefreshProbeNoArgument(manager, "iconImageCache");
    id rootController = CNDRefreshProbeNoArgument(
        manager, "rootFolderController");
    CNDRefreshProbeLogMethod(rootController, "iconImageCache");
    CNDRefreshProbeLogMethod(rootController, "setIconImageCache:");
    id rootCache = CNDRefreshProbeNoArgument(
        rootController, "iconImageCache");
    id rootView = CNDRefreshProbeNoArgument(
        rootController, "folderViewIfLoaded");
    id rootViewCache = CNDRefreshProbeNoArgument(rootView, "iconImageCache");
    CNDRefreshProbeLogMethod(rootView, "setIconImageCache:");
    CNDRefreshProbeLog(
        "[CND_REFRESH] target-root-cache manager=%p root=%p/%s "
        "root-cache=%p current=%d view=%p/%s view-cache=%p current=%d\n",
        managerCache, rootController,
        rootController ? class_getName([rootController class]) : "-",
        rootCache, rootCache == managerCache ? 1 : 0,
        rootView, rootView ? class_getName([rootView class]) : "-",
        rootViewCache, rootViewCache == managerCache ? 1 : 0);

    enum { LIST_CAP = 64 };
    id __unsafe_unretained listViews[LIST_CAP] = { nil };
    NSUInteger listCount = 0U;
    static const char *const managerListSelectors[] = {
        "currentRootIconList", "dockListView", "effectiveDockListView",
        "floatingDockListView", "floatingDockSuggestionsListView",
    };
    for (size_t index = 0U;
         index < sizeof(managerListSelectors) /
             sizeof(managerListSelectors[0]); index++) {
        CNDRefreshProbeAddObject(
            listViews, &listCount, LIST_CAP,
            CNDRefreshProbeNoArgument(manager, managerListSelectors[index]));
    }
    static const char *const rootListSelectors[] = {
        "currentIconListView", "dockIconListView", "dockListView",
    };
    for (size_t index = 0U;
         index < sizeof(rootListSelectors) / sizeof(rootListSelectors[0]);
         index++) {
        CNDRefreshProbeAddObject(
            listViews, &listCount, LIST_CAP,
            CNDRefreshProbeNoArgument(
                rootController, rootListSelectors[index]));
    }
    for (id list in CNDRefreshProbeCollectionObjects(
            CNDRefreshProbeNoArgument(
                rootController, "visibleIconListViews"))) {
        CNDRefreshProbeAddObject(listViews, &listCount, LIST_CAP, list);
    }
    for (id list in CNDRefreshProbeCollectionObjects(
            CNDRefreshProbeNoArgument(rootView, "allIconListViews"))) {
        CNDRefreshProbeAddObject(listViews, &listCount, LIST_CAP, list);
    }
    for (NSUInteger index = 0U; index < listCount; index++) {
        id list = listViews[index];
        id cache = CNDRefreshProbeNoArgument(list, "iconImageCache");
        CNDRefreshProbeLogMethod(list, "setIconImageCache:");
        CNDRefreshProbeLog(
            "[CND_REFRESH] target-list-cache index=%lu list=%p/%s "
            "cache=%p/%s current=%d icon-location=%s\n",
            (unsigned long)index, list,
            list ? class_getName([list class]) : "-", cache,
            cache ? class_getName([cache class]) : "-",
            cache == managerCache ? 1 : 0,
            [CNDRefreshProbeNoArgument(list, "iconLocation") UTF8String]
                ?: "-");
    }
    id leafCollection = CNDRefreshProbeNoArgument(
        model, "leafIconsUniquedByApplicationBundleIdentifier");
    NSArray *leafObjects = CNDRefreshProbeCollectionObjects(leafCollection);
    enum { ICON_CAP = 32 };
    id __unsafe_unretained icons[ICON_CAP] = { nil };
    NSUInteger iconCount = 0U;
    CNDRefreshProbeAddObject(icons, &iconCount, ICON_CAP, canonical);
    for (id icon in leafObjects) {
        if ([CNDRefreshProbeBundleForIcon(icon) isEqualToString:target]) {
            CNDRefreshProbeAddObject(icons, &iconCount, ICON_CAP, icon);
        }
    }
    for (NSUInteger index = 0U; index < iconCount; index++) {
        CNDRefreshProbeLogIconConsumer(
            index == 0U ? "canonical-or-leaf" : "leaf",
            icons[index], managerCache, rootController);
    }

    id application = [UIApplication sharedApplication];
    id switcherController = CNDRefreshProbeNoArgument(
        application, "_switcherController");
    id switcherViewController = CNDRefreshProbeNoArgument(
        switcherController, "contentViewController");
    id controllerMap = CNDRefreshProbeIvarObject(
        switcherViewController, "_appLayoutToTitleItemController");
    NSArray *titleControllers = CNDRefreshProbeCollectionObjects(
        controllerMap);
    NSUInteger titleCount = MIN(titleControllers.count, 128U);
    NSUInteger matchedSwitcherIcons = 0U;
    for (NSUInteger controllerIndex = 0U;
         controllerIndex < titleCount; controllerIndex++) {
        id controller = titleControllers[controllerIndex];
        id displayItems = CNDRefreshProbeIvarObject(
            controller, "_displayItems");
        id displayItemToIcon = CNDRefreshProbeIvarObject(
            controller, "_displayItemToIcon");
        NSArray *items = CNDRefreshProbeCollectionObjects(displayItems);
        NSUInteger itemCount = MIN(items.count, 16U);
        for (NSUInteger itemIndex = 0U; itemIndex < itemCount; itemIndex++) {
            id item = items[itemIndex];
            id bundle = CNDRefreshProbeNoArgument(item, "bundleIdentifier");
            if (![bundle isEqualToString:target]) continue;
            id icon = [displayItemToIcon respondsToSelector:
                    @selector(objectForKey:)]
                ? [displayItemToIcon objectForKey:item] : nil;
            bool known = false;
            for (NSUInteger iconIndex = 0U;
                 iconIndex < iconCount; iconIndex++) {
                known |= icons[iconIndex] == icon;
            }
            CNDRefreshProbeLog(
                "[CND_REFRESH] target-switcher controller=%p/%s "
                "display-item=%p/%s icon=%p/%s known-home-icon=%d "
                "map=%p/%s\n", controller,
                controller ? class_getName([controller class]) : "-",
                item, item ? class_getName([item class]) : "-",
                icon, icon ? class_getName([icon class]) : "-",
                known ? 1 : 0, displayItemToIcon,
                displayItemToIcon
                    ? class_getName([displayItemToIcon class]) : "-");
            CNDRefreshProbeLogIconConsumer(
                "switcher-map", icon, managerCache, rootController);
            matchedSwitcherIcons++;
        }
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] target-consumers summary bundle=%s canonical=%p "
        "icons=%lu leaf-total=%lu lists=%lu switcher-controllers=%lu "
        "switcher-matches=%lu manager-cache=%p root=%p main=%d\n",
        target.UTF8String, canonical, (unsigned long)iconCount,
        (unsigned long)leafObjects.count, (unsigned long)listCount,
        (unsigned long)titleControllers.count,
        (unsigned long)matchedSwitcherIcons, managerCache, rootController,
        [NSThread isMainThread] ? 1 : 0);
    return canonical && iconCount > 0U &&
        leafObjects.count <= 2048U && listCount <= LIST_CAP &&
        titleControllers.count <= 128U;
}

static bool CNDRefreshProbeRootCacheRebind(id manager)
{
    id cache = CNDRefreshProbeNoArgument(manager, "iconImageCache");
    id controller = CNDRefreshProbeNoArgument(
        manager, "rootFolderController");
    id oldCache = CNDRefreshProbeNoArgument(controller, "iconImageCache");
    CNDRefreshProbeLogMethod(controller, "setIconImageCache:");
    SEL setter = sel_registerName("setIconImageCache:");
    Method method = controller
        ? class_getInstanceMethod([controller class], setter) : NULL;
    bool abi = method &&
        !strcmp(method_getTypeEncoding(method), "v24@0:8@16");
    if (!cache || !controller || !abi) return false;
    ((void (*)(id, SEL, id))objc_msgSend)(controller, setter, cache);

    id folderView = CNDRefreshProbeNoArgument(
        controller, "folderViewIfLoaded");
    id rootCache = CNDRefreshProbeNoArgument(controller, "iconImageCache");
    id viewCache = CNDRefreshProbeNoArgument(folderView, "iconImageCache");
    NSArray *lists = CNDRefreshProbeCollectionObjects(
        CNDRefreshProbeNoArgument(folderView, "allIconListViews"));
    NSUInteger bounded = MIN(lists.count, 64U);
    NSUInteger current = 0U;
    for (NSUInteger index = 0U; index < bounded; index++) {
        id list = lists[index];
        id listCache = CNDRefreshProbeNoArgument(list, "iconImageCache");
        if (listCache == cache) current++;
        CNDRefreshProbeLog(
            "[CND_REFRESH] root-cache-rebind list=%p/%s cache=%p "
            "current=%d\n", list, class_getName([list class]), listCache,
            listCache == cache ? 1 : 0);
    }
    CNDRefreshProbeLog(
        "[CND_REFRESH] root-cache-rebind controller=%p old=%p new=%p "
        "root=%p view=%p lists=%lu/%lu truncated=%d main=%d\n",
        controller, oldCache, cache, rootCache, viewCache,
        (unsigned long)current, (unsigned long)lists.count,
        lists.count > 64U ? 1 : 0,
        [NSThread isMainThread] ? 1 : 0);
    return rootCache == cache && viewCache == cache &&
        lists.count <= 64U && current == lists.count;
}

static bool CNDRefreshProbeBoundedRefresh(id controller, id manager)
{
    if (!controller || !manager) return false;

    bool ok = CNDRefreshProbeVoidNoArgument(
        manager, "resetAllIconImageCaches");

    id caches[8] = {0};
    NSUInteger cacheCount = 0U;
    static const char *const controllerCacheSelectors[] = {
        "notificationIconImageCache",
        "tableUIIconImageCache",
        "appSwitcherHeaderIconImageCache",
    };
    for (NSUInteger index = 0;
         index < sizeof(controllerCacheSelectors) /
                     sizeof(controllerCacheSelectors[0]); index++) {
        id cache = CNDRefreshProbeNoArgument(
            controller, controllerCacheSelectors[index]);
        if (!cache) continue;
        bool duplicate = false;
        for (NSUInteger existing = 0; existing < cacheCount; existing++) {
            duplicate |= caches[existing] == cache;
        }
        if (!duplicate && cacheCount < sizeof(caches) / sizeof(caches[0])) {
            caches[cacheCount++] = cache;
        }
    }

    id library = CNDRefreshProbeNoArgument(
        manager, "trailingLibraryViewController");
    if (!library) {
        library = CNDRefreshProbeNoArgument(
            manager, "overlayLibraryViewController");
    }
    id libraryCache = CNDRefreshProbeNoArgument(library, "iconImageCache");
    if (libraryCache) {
        bool duplicate = false;
        for (NSUInteger existing = 0; existing < cacheCount; existing++) {
            duplicate |= caches[existing] == libraryCache;
        }
        if (!duplicate && cacheCount < sizeof(caches) / sizeof(caches[0])) {
            caches[cacheCount++] = libraryCache;
        }
    }

    for (NSUInteger index = 0; index < cacheCount; index++) {
        ok &= CNDRefreshProbeVoidNoArgument(
            caches[index], "purgeAllCachedImages");
    }

    id folderCache = CNDRefreshProbeNoArgument(
        manager, "folderIconImageCache");
    ok &= CNDRefreshProbeVoidNoArgument(
        folderCache, "rebuildAllCachedFolderImages");

    /* SBHIconManager -relayout is the stock bounded consumer refresh. On the
     * unlocked iOS 26 VM it rebinds visible Home SBIconViews and drives the
     * SBLibraryViewController pod reload without walking UIKit's view tree. */
    ok &= CNDRefreshProbeVoidNoArgument(manager, "relayout");
    return ok;
}

static void CNDRefreshProbeRunAction(void)
{
    if (!strcmp(CND_REFRESH_PROBE_ACTION, "inventory")) {
        CNDRefreshProbeInventory();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "notification-inventory")) {
        CNDRefreshProbeNotificationInventory();
    }

    id controller = CNDRefreshProbeIconController();
    id manager = CNDRefreshProbeIconManager(controller);
    id model = CNDRefreshProbeIconModel(manager);
    CNDRefreshProbeLog(
        "[CND_REFRESH] roots controller=%p/%s manager=%p/%s model=%p/%s "
        "action=%s\n", controller,
        controller ? class_getName([controller class]) : "-", manager,
        manager ? class_getName([manager class]) : "-", model,
        model ? class_getName([model class]) : "-", CND_REFRESH_PROBE_ACTION);

    static const char *const controllerGetters[] = {
        "notificationIconImageCache", "tableUIIconImageCache",
        "appSwitcherHeaderIconImageCache",
    };
    static const char *const managerGetters[] = {
        "iconImageCache", "folderIconImageCache",
        "trailingLibraryViewController", "overlayLibraryViewController",
        "rootFolderController", "model", "iconModel",
    };
    for (size_t index = 0;
         index < sizeof(controllerGetters) / sizeof(controllerGetters[0]);
         index++) {
        CNDRefreshProbeLogGetter(controller, controllerGetters[index]);
    }
    for (size_t index = 0;
         index < sizeof(managerGetters) / sizeof(managerGetters[0]); index++) {
        CNDRefreshProbeLogGetter(manager, managerGetters[index]);
    }

    bool invoked = false;
    if (!strcmp(CND_REFRESH_PROBE_ACTION, "reset")) {
        invoked = CNDRefreshProbeVoidNoArgument(
            manager, "resetAllIconImageCaches");
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "cache-reset-inventory")) {
        invoked = CNDRefreshProbeCacheResetInventory(controller, manager);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "library-search-query")) {
        invoked = CNDRefreshProbeLibrarySearchQuery(manager);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "library-table")) {
        invoked = CNDRefreshProbeLibraryTableRefresh(manager);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "switcher-cache")) {
        id cache = CNDRefreshProbeNoArgument(
            controller, "appSwitcherHeaderIconImageCache");
        CNDRefreshProbeLogCacheState("before", "switcher", cache);
        invoked = CNDRefreshProbeVoidNoArgument(
            cache, "purgeAllCachedImages");
        CNDRefreshProbeLogCacheState("after", "switcher", cache);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "switcher-titles")) {
        invoked = CNDRefreshProbeSwitcherTitles();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "switcher-retained")) {
        invoked = CNDRefreshProbeSwitcherRetainedConsumers(false);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "switcher-retained-repaint")) {
        invoked = CNDRefreshProbeSwitcherRetainedConsumers(true);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "switcher-inventory")) {
        invoked = CNDRefreshProbeSwitcherInventory();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "reload")) {
        invoked = CNDRefreshProbeVoidNoArgument(model, "reloadIcons");
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "target-icon")) {
        invoked = CNDRefreshProbeTargetIconReload(
            manager, model, false, false);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "target-visible")) {
        invoked = CNDRefreshProbeTargetIconReload(
            manager, model, true, false);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "target-cache")) {
        invoked = CNDRefreshProbeTargetIconReload(
            manager, model, false, true);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "target-consumers")) {
        invoked = CNDRefreshProbeTargetConsumers(manager, model);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "root-cache-rebind")) {
        invoked = CNDRefreshProbeRootCacheRebind(manager);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "folder")) {
        id cache = CNDRefreshProbeNoArgument(manager, "folderIconImageCache");
        invoked = CNDRefreshProbeVoidNoArgument(
            cache, "rebuildAllCachedFolderImages");
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "folder-source")) {
        id cache = CNDRefreshProbeNoArgument(manager, "folderIconImageCache");
        id source = CNDRefreshProbeNoArgument(cache, "iconImageCache");
        id shared = CNDRefreshProbeNoArgument(cache, "sharedCache");
        id sharedSource = CNDRefreshProbeNoArgument(
            shared, "iconImageCache");
        CNDRefreshProbeLogCacheState("before", "folder-inner", source);
        CNDRefreshProbeLogCacheState(
            "before", "folder-shared-inner", sharedSource);
        bool purged = CNDRefreshProbeVoidNoArgument(
            source, "purgeAllCachedImages");
        bool purgedShared = sharedSource == source ||
            CNDRefreshProbeVoidNoArgument(
                sharedSource, "purgeAllCachedImages");
        bool rebuilt = CNDRefreshProbeVoidNoArgument(
            cache, "rebuildAllCachedFolderImages");
        CNDRefreshProbeLogCacheState("after", "folder-inner", source);
        CNDRefreshProbeLogCacheState(
            "after", "folder-shared-inner", sharedSource);
        CNDRefreshProbeLog(
            "[CND_REFRESH] folder-source cache=%p source=%p shared=%p "
            "shared-source=%p aliased=%d purged=%d purged-shared=%d "
            "rebuilt=%d main=%d\n", cache, source, shared, sharedSource,
            source == sharedSource ? 1 : 0, purged ? 1 : 0,
            purgedShared ? 1 : 0, rebuilt ? 1 : 0,
            [NSThread isMainThread] ? 1 : 0);
        invoked = purged && purgedShared && rebuilt;
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "layout")) {
        invoked = CNDRefreshProbeLayout(manager);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "relayout")) {
        invoked = CNDRefreshProbeVoidNoArgument(manager, "relayout");
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "unlock")) {
        invoked = CNDRefreshProbeUnlock();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "force-unlock")) {
        invoked = CNDRefreshProbeForceUnlock();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "library")) {
        static const char *const selectors[] = {
            "trailingLibraryViewController",
            "overlayLibraryViewController",
        };
        for (size_t index = 0;
             index < sizeof(selectors) / sizeof(selectors[0]); index++) {
            id library = CNDRefreshProbeNoArgument(manager, selectors[index]);
            if (!library) continue;
            id folderController = CNDRefreshProbeNoArgument(
                library, "folderController");
            bool reloaded = CNDRefreshProbeVoidNoArgument(
                folderController, "_reloadAppIcons");
            bool enqueued = CNDRefreshProbeVoidNoArgument(
                library, "_enqueueAppLibraryUpdate");
            invoked |= reloaded || enqueued;
        }
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION, "bounded")) {
        invoked = CNDRefreshProbeBoundedRefresh(controller, manager);
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "notification-reload")) {
        invoked = CNDRefreshProbeNotificationReload();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "notification-cache-purge")) {
        invoked = CNDRefreshProbeNotificationCachePurge();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "notification-consumers")) {
        invoked = CNDRefreshProbeNotificationConsumers();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "notification-recipe")) {
        invoked = CNDRefreshProbeNotificationRecipe();
    } else if (!strcmp(CND_REFRESH_PROBE_ACTION,
                       "notification-sources")) {
        invoked = CNDRefreshProbeNotificationSources();
    } else {
        invoked = !strcmp(CND_REFRESH_PROBE_ACTION, "inventory") ||
            !strcmp(CND_REFRESH_PROBE_ACTION, "notification-inventory");
    }
    if (!gCNDRefreshProbeCompletionDeferred) {
        CNDRefreshProbeLog(
            "[CND_REFRESH] PROBE_COMPLETE pid=%d action=%s invoked=%d\n",
            getpid(), CND_REFRESH_PROBE_ACTION, invoked ? 1 : 0);
    }
}

__attribute__((constructor))
static void CNDRefreshProbeStart(void)
{
    @autoreleasepool {
        typedef int64_t (*ConsumeFunction)(const char *);
        ConsumeFunction consume = (ConsumeFunction)dlsym(
            RTLD_DEFAULT, "sandbox_extension_consume");
        int64_t token = CND_REFRESH_PROBE_OUTPUT_TOKEN[0] && consume
            ? consume(CND_REFRESH_PROBE_OUTPUT_TOKEN) : -1;
        gCNDRefreshProbeFD = open(
            CND_REFRESH_PROBE_OUTPUT_PATH,
            O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
        CNDRefreshProbeLog(
            "[CND_REFRESH] START pid=%d process=%s token=%lld action=%s\n",
            getpid(), getprogname(), (long long)token,
            CND_REFRESH_PROBE_ACTION);
        (void)dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardHome.framework/"
            "SpringBoardHome", RTLD_NOW | RTLD_LOCAL);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                     500 * NSEC_PER_MSEC),
                       dispatch_get_main_queue(), ^{
            CNDRefreshProbeRunAction();
        });
    }
}
