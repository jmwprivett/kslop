#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <unistd.h>

#ifndef CND_PULSAR_PERSISTENCE_REPORT_PATH
#define CND_PULSAR_PERSISTENCE_REPORT_PATH \
    "/var/tmp/cyanide-pulsar-connectivity-persistence.log"
#endif

#ifndef CND_PULSAR_PERSISTENCE_ASSET_DIRECTORY
#define CND_PULSAR_PERSISTENCE_ASSET_DIRECTORY "/var/tmp/cnd-pulsar-persistence"
#endif

#ifndef CND_PULSAR_PERSISTENCE_EXPECTED_PID
#define CND_PULSAR_PERSISTENCE_EXPECTED_PID 0
#endif

#ifndef CND_PULSAR_PERSISTENCE_HOLD_SECONDS
#define CND_PULSAR_PERSISTENCE_HOLD_SECONDS 36
#endif

/*
 * Bounded VM-only persistence canary.
 *
 * It changes presentation objects only. The radio/control action methods are
 * never called. Stock setter arguments are captured, the stable delivery
 * methods are hooked for the duration of the canary, and every method and
 * captured object is restored before completion.
 */

typedef void (*CNDObjectSetterIMP)(id, SEL, id);
typedef void (*CNDBoolSetterIMP)(id, SEL, BOOL);

static IMP gButtonGlyphOriginal;
static IMP gButtonSelectedGlyphOriginal;
static IMP gLabeledGlyphOriginal;
static IMP gLabeledEnabledOriginal;
static Method gButtonGlyphMethod;
static Method gButtonSelectedGlyphMethod;
static Method gLabeledGlyphMethod;
static Method gLabeledEnabledMethod;
static BOOL gActive;
static BOOL gRestored;
static BOOL gRestoreVerified;
static NSUInteger gHookHits;
static NSUInteger gNewReceiverHits;
static NSMutableDictionary<NSString *, NSDictionary<NSString *, UIImage *> *> *gArtwork;
static NSMutableDictionary<NSValue *, NSMutableDictionary<NSString *, id> *> *gRecords;
static NSMutableSet<NSValue *> *gSeededReceivers;

static void CNDLog(NSString *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);
    FILE *file = fopen(CND_PULSAR_PERSISTENCE_REPORT_PATH, "a");
    if (!file) return;
    fprintf(file, "[CND_PULSAR_PERSISTENCE] %s\n", line.UTF8String ?: "-");
    fclose(file);
}

static BOOL CNDMethodHasTypes(Class cls, SEL selector, const char *expected)
{
    Method method = cls && selector ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    return types && expected && strcmp(types, expected) == 0;
}

static id CNDGetter(id object, const char *name)
{
    SEL selector = name ? sel_registerName(name) : NULL;
    if (!object || !selector || ![object respondsToSelector:selector]) return nil;
    return ((id (*)(id, SEL))objc_msgSend)(object, selector);
}

static BOOL CNDBoolGetter(id object, const char *name, BOOL fallback)
{
    SEL selector = name ? sel_registerName(name) : NULL;
    if (!object || !selector || ![object respondsToSelector:selector]) {
        return fallback;
    }
    return ((BOOL (*)(id, SEL))objc_msgSend)(object, selector);
}

static NSString *CNDKindForObject(id object)
{
    NSString *name = object ? NSStringFromClass([object class]) : @"";
    if ([name isEqualToString:@"CCUIWiFiModuleViewController"]) return @"wifi";
    if ([name isEqualToString:@"CCUIBluetoothModuleViewController"]) return @"bluetooth";
    if ([name isEqualToString:@"CCUIAirDropModuleViewController"]) return @"airDrop";
    if ([name isEqualToString:@"CCUIConnectivityAirplaneViewController"]) return @"airplaneMode";
    if ([name isEqualToString:@"CCUIConnectivityCellularDataViewController"]) return @"cellular";
    if ([name isEqualToString:@"CCUIConnectivityHotspotViewController"]) return @"hotspot";
    return nil;
}

static NSMutableDictionary<NSString *, id> *CNDRecord(id receiver, BOOL create)
{
    if (!receiver) return nil;
    NSValue *key = [NSValue valueWithNonretainedObject:receiver];
    NSMutableDictionary *record = gRecords[key];
    if (!record && create) {
        record = [@{ @"receiver": receiver,
                     @"class": NSStringFromClass([receiver class]) ?: @"" }
                  mutableCopy];
        gRecords[key] = record;
    }
    return record;
}

static void CNDCapture(id receiver, NSString *field, id value)
{
    NSMutableDictionary *record = CNDRecord(receiver, YES);
    if (!record[field]) record[field] = value ?: NSNull.null;
}

static NSDictionary<NSString *, UIImage *> *CNDImages(id receiver)
{
    NSString *kind = CNDKindForObject(receiver);
    return kind.length ? gArtwork[kind] : nil;
}

static CNDObjectSetterIMP CNDGlyphOriginalForReceiver(id receiver)
{
    Class labeled = NSClassFromString(@"CCUILabeledRoundButtonViewController");
    if (labeled && [receiver isKindOfClass:labeled]) {
        return (CNDObjectSetterIMP)gLabeledGlyphOriginal;
    }
    return (CNDObjectSetterIMP)gButtonGlyphOriginal;
}

static void CNDSetGlyphReplacement(id receiver, SEL selector, id stockImage)
{
    CNDObjectSetterIMP original = CNDGlyphOriginalForReceiver(receiver);
    NSDictionary *images = gActive ? CNDImages(receiver) : nil;
    if (!original) return;
    if (!images) {
        original(receiver, selector, stockImage);
        return;
    }
    CNDCapture(receiver, @"glyph", stockImage);
    BOOL selected = CNDBoolGetter(receiver, "isSelected", NO) ||
        CNDBoolGetter(receiver, "isEnabled", NO);
    UIImage *theme = images[selected ? @"selected" : @"standard"] ?:
        images[@"standard"];
    original(receiver, selector, theme ?: stockImage);
    NSValue *key = [NSValue valueWithNonretainedObject:receiver];
    if (![gSeededReceivers containsObject:key]) gNewReceiverHits++;
    gHookHits++;
    CNDLog(@"HOOK selector=setGlyphImage: receiver=%p/%@ kind=%@ selected=%d hit=%lu",
           receiver, NSStringFromClass([receiver class]),
           CNDKindForObject(receiver), selected, (unsigned long)gHookHits);
}

static void CNDSetSelectedGlyphReplacement(id receiver, SEL selector,
                                           id stockImage)
{
    CNDObjectSetterIMP original = (CNDObjectSetterIMP)gButtonSelectedGlyphOriginal;
    NSDictionary *images = gActive ? CNDImages(receiver) : nil;
    if (!original) return;
    if (!images) {
        original(receiver, selector, stockImage);
        return;
    }
    CNDCapture(receiver, @"selectedGlyph", stockImage);
    original(receiver, selector, images[@"selected"] ?: images[@"standard"] ?:
             stockImage);
    NSValue *key = [NSValue valueWithNonretainedObject:receiver];
    if (![gSeededReceivers containsObject:key]) gNewReceiverHits++;
    gHookHits++;
}

static void CNDSetEnabledReplacement(id receiver, SEL selector, BOOL enabled)
{
    CNDBoolSetterIMP original = (CNDBoolSetterIMP)gLabeledEnabledOriginal;
    if (!original) return;
    original(receiver, selector, enabled);
    NSDictionary *images = gActive ? CNDImages(receiver) : nil;
    if (!images) return;

    id stock = CNDGetter(receiver, "glyphImage");
    CNDCapture(receiver, @"glyph", stock);
    CNDCapture(receiver, @"enabled", @(enabled));
    UIImage *theme = images[enabled ? @"selected" : @"standard"] ?:
        images[@"standard"];
    CNDObjectSetterIMP glyphOriginal = CNDGlyphOriginalForReceiver(receiver);
    if (glyphOriginal && theme) {
        glyphOriginal(receiver, sel_registerName("setGlyphImage:"), theme);
        NSValue *key = [NSValue valueWithNonretainedObject:receiver];
        if (![gSeededReceivers containsObject:key]) gNewReceiverHits++;
        gHookHits++;
        CNDLog(@"HOOK selector=setEnabled: receiver=%p/%@ enabled=%d hit=%lu",
               receiver, NSStringFromClass([receiver class]), enabled,
               (unsigned long)gHookHits);
    }
}

static UIViewController *CNDFindController(UIViewController *controller,
                                           Class target)
{
    if (!controller || !target) return nil;
    if ([controller isKindOfClass:target]) return controller;
    UIViewController *found = CNDFindController(
        controller.presentedViewController, target);
    if (found) return found;
    for (UIViewController *child in controller.childViewControllers) {
        found = CNDFindController(child, target);
        if (found) return found;
    }
    return nil;
}

static UIViewController *CNDConnectivityController(void)
{
    Class target = NSClassFromString(@"CCUIConnectivityModuleViewController");
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (![scene isKindOfClass:UIWindowScene.class]) continue;
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            UIViewController *found = CNDFindController(
                window.rootViewController, target);
            if (found) return found;
        }
    }
    return nil;
}

static NSArray<id> *CNDConnectivityChildren(void)
{
    id parent = CNDConnectivityController();
    if (!parent) return @[];
    const char *getters[] = {
        "wifiModuleViewController", "bluetoothModuleViewController",
        "airDropModuleViewController", "airplaneButtonViewController",
        "expandedAirplaneButtonViewController",
        "cellularDataButtonViewController",
        "expandedCellularDataButtonViewController",
        "hotspotButtonViewController", "expandedHotspotButtonViewController",
    };
    NSMutableArray *children = [NSMutableArray array];
    NSMutableSet<NSValue *> *seen = [NSMutableSet set];
    for (NSUInteger index = 0;
         index < sizeof(getters) / sizeof(getters[0]); index++) {
        id child = CNDGetter(parent, getters[index]);
        NSValue *key = child ? [NSValue valueWithNonretainedObject:child] : nil;
        if (child && CNDKindForObject(child) && ![seen containsObject:key]) {
            [seen addObject:key];
            [children addObject:child];
        }
    }
    return children;
}

static void CNDSeed(void)
{
    for (id child in CNDConnectivityChildren()) {
        NSValue *key = [NSValue valueWithNonretainedObject:child];
        [gSeededReceivers addObject:key];
        NSDictionary *images = CNDImages(child);
        if (!images) continue;
        SEL glyphSetter = sel_registerName("setGlyphImage:");
        if ([child respondsToSelector:glyphSetter]) {
            id stock = CNDGetter(child, "glyphImage");
            CNDCapture(child, @"glyph", stock);
            ((void (*)(id, SEL, id))objc_msgSend)(
                child, glyphSetter, stock ?: images[@"standard"]);
        }
        SEL selectedSetter = sel_registerName("setSelectedGlyphImage:");
        if ([child respondsToSelector:selectedSetter]) {
            id stock = CNDGetter(child, "selectedGlyphImage");
            CNDCapture(child, @"selectedGlyph", stock);
            ((void (*)(id, SEL, id))objc_msgSend)(
                child, selectedSetter, stock ?: images[@"selected"]);
        }
    }
}

static void CNDVerify(NSString *tag)
{
    NSUInteger found = 0;
    NSUInteger themed = 0;
    for (id child in CNDConnectivityChildren()) {
        NSDictionary *images = CNDImages(child);
        if (!images) continue;
        found++;
        BOOL selected = CNDBoolGetter(child, "isSelected", NO) ||
            CNDBoolGetter(child, "isEnabled", NO);
        id expected = images[selected ? @"selected" : @"standard"] ?:
            images[@"standard"];
        id actual = CNDGetter(child, "glyphImage");
        if (actual == expected) themed++;
    }
    CNDLog(@"VERIFY tag=%@ found=%lu themed=%lu records=%lu hookHits=%lu newReceivers=%lu",
           tag, (unsigned long)found, (unsigned long)themed,
           (unsigned long)gRecords.count, (unsigned long)gHookHits,
           (unsigned long)gNewReceiverHits);
}

static BOOL CNDInstallHook(Class cls, const char *name, const char *types,
                           IMP replacement, Method *methodOut,
                           IMP *originalOut)
{
    SEL selector = sel_registerName(name);
    if (!CNDMethodHasTypes(cls, selector, types)) return NO;
    Method method = class_getInstanceMethod(cls, selector);
    IMP original = method_getImplementation(method);
    if (!method || !original || !replacement) return NO;
    IMP replaced = method_setImplementation(method, replacement);
    if (replaced != original || method_getImplementation(method) != replacement) {
        if (replaced) method_setImplementation(method, replaced);
        return NO;
    }
    *methodOut = method;
    *originalOut = original;
    return YES;
}

static UIImage *CNDLoadImage(NSString *kind, NSString *state)
{
    NSString *path = [NSString stringWithFormat:@"%s/%@-%@.png",
                      CND_PULSAR_PERSISTENCE_ASSET_DIRECTORY, kind, state];
    UIImage *image = [UIImage imageWithContentsOfFile:path];
    return [image imageWithRenderingMode:UIImageRenderingModeAlwaysTemplate];
}

static BOOL CNDLoadArtwork(void)
{
    NSDictionary *files = @{
        @"wifi": @"wifi", @"bluetooth": @"bluetooth",
        @"airDrop": @"airdrop", @"airplaneMode": @"airplane",
        @"cellular": @"cellular", @"hotspot": @"hotspot",
    };
    gArtwork = [NSMutableDictionary dictionary];
    for (NSString *kind in files) {
        UIImage *standard = CNDLoadImage(files[kind], @"standard");
        UIImage *selected = CNDLoadImage(files[kind], @"selected");
        if (!standard || !selected) return NO;
        gArtwork[kind] = @{ @"standard": standard, @"selected": selected };
    }
    return YES;
}

static BOOL CNDInstall(void)
{
    Class button = NSClassFromString(@"CCUIButtonModuleViewController");
    Class labeled = NSClassFromString(@"CCUILabeledRoundButtonViewController");
    if (!button || !labeled || !CNDLoadArtwork()) return NO;
    gRecords = [NSMutableDictionary dictionary];
    gSeededReceivers = [NSMutableSet set];

    BOOL ok = CNDInstallHook(
        button, "setGlyphImage:", "v24@0:8@16",
        (IMP)CNDSetGlyphReplacement, &gButtonGlyphMethod,
        &gButtonGlyphOriginal);
    ok = ok && CNDInstallHook(
        button, "setSelectedGlyphImage:", "v24@0:8@16",
        (IMP)CNDSetSelectedGlyphReplacement, &gButtonSelectedGlyphMethod,
        &gButtonSelectedGlyphOriginal);
    ok = ok && CNDInstallHook(
        labeled, "setGlyphImage:", "v24@0:8@16",
        (IMP)CNDSetGlyphReplacement, &gLabeledGlyphMethod,
        &gLabeledGlyphOriginal);
    ok = ok && CNDInstallHook(
        labeled, "setEnabled:", "v20@0:8B16",
        (IMP)CNDSetEnabledReplacement, &gLabeledEnabledMethod,
        &gLabeledEnabledOriginal);
    if (!ok) return NO;
    gActive = YES;
    CNDSeed();
    return YES;
}

static BOOL CNDRestoreMethod(Method method, IMP original, IMP replacement)
{
    if (!method || !original) return NO;
    IMP observed = method_getImplementation(method);
    if (observed == original) return YES;
    if (observed != replacement) return NO;
    IMP replaced = method_setImplementation(method, original);
    return replaced == replacement && method_getImplementation(method) == original;
}

static void CNDRestore(void)
{
    if (gRestored) return;
    gRestored = YES;
    gActive = NO;
    BOOL methods = YES;
    methods = CNDRestoreMethod(
        gLabeledEnabledMethod, gLabeledEnabledOriginal,
        (IMP)CNDSetEnabledReplacement) && methods;
    methods = CNDRestoreMethod(
        gLabeledGlyphMethod, gLabeledGlyphOriginal,
        (IMP)CNDSetGlyphReplacement) && methods;
    methods = CNDRestoreMethod(
        gButtonSelectedGlyphMethod, gButtonSelectedGlyphOriginal,
        (IMP)CNDSetSelectedGlyphReplacement) && methods;
    methods = CNDRestoreMethod(
        gButtonGlyphMethod, gButtonGlyphOriginal,
        (IMP)CNDSetGlyphReplacement) && methods;

    NSUInteger restored = 0;
    BOOL objects = YES;
    for (NSMutableDictionary *record in gRecords.allValues) {
        id receiver = record[@"receiver"];
        id glyph = record[@"glyph"];
        id selected = record[@"selectedGlyph"];
        if (glyph) {
            CNDObjectSetterIMP original = CNDGlyphOriginalForReceiver(receiver);
            if (original) {
                original(receiver, sel_registerName("setGlyphImage:"),
                         glyph == NSNull.null ? nil : glyph);
                id expected = glyph == NSNull.null ? nil : glyph;
                objects = objects && CNDGetter(receiver, "glyphImage") == expected;
            } else {
                objects = NO;
            }
        }
        if (selected && gButtonSelectedGlyphOriginal) {
            id expected = selected == NSNull.null ? nil : selected;
            ((CNDObjectSetterIMP)gButtonSelectedGlyphOriginal)(
                receiver, sel_registerName("setSelectedGlyphImage:"),
                expected);
            objects = objects &&
                CNDGetter(receiver, "selectedGlyphImage") == expected;
        }
        if ([CNDKindForObject(receiver) isEqualToString:@"airplaneMode"] &&
            gLabeledEnabledOriginal) {
            BOOL enabled = CNDBoolGetter(receiver, "isEnabled", NO);
            ((CNDBoolSetterIMP)gLabeledEnabledOriginal)(
                receiver, sel_registerName("setEnabled:"), enabled);
        }
        restored++;
    }
    gRestoreVerified = methods && objects;
    CNDLog(@"RESTORED methods=%d objects=%lu objectReadback=%d hookHits=%lu newReceivers=%lu",
           methods, (unsigned long)restored, objects,
           (unsigned long)gHookHits, (unsigned long)gNewReceiverHits);
}

__attribute__((constructor))
static void CNDPulsarPersistenceStart(void)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        unlink(CND_PULSAR_PERSISTENCE_REPORT_PATH);
        if (CND_PULSAR_PERSISTENCE_EXPECTED_PID > 1 &&
            getpid() != CND_PULSAR_PERSISTENCE_EXPECTED_PID) {
            CNDLog(@"COMPLETE status=refused-pid pid=%d expected=%d",
                   getpid(), CND_PULSAR_PERSISTENCE_EXPECTED_PID);
            return;
        }
        BOOL installed = CNDInstall();
        CNDLog(@"READY pid=%d installed=%d seeded=%lu hooks=4 noRadioWrite=1 noSystemWrite=1 holdSeconds=%d",
               getpid(), installed, (unsigned long)gSeededReceivers.count,
               CND_PULSAR_PERSISTENCE_HOLD_SECONDS);
        if (!installed) {
            CNDRestore();
            CNDLog(@"COMPLETE status=refused-contract");
            return;
        }

        __block NSUInteger tick = 0;
        __block void (^verify)(void) = nil;
        verify = ^{
            if (gRestored) return;
            tick++;
            CNDVerify([NSString stringWithFormat:@"tick-%lu",
                       (unsigned long)tick]);
            if (tick < CND_PULSAR_PERSISTENCE_HOLD_SECONDS) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                    (int64_t)NSEC_PER_SEC), dispatch_get_main_queue(), verify);
                return;
            }
            CNDRestore();
            BOOL success = gHookHits > 0 && gRecords.count > 0 &&
                gRestoreVerified;
            CNDLog(@"COMPLETE status=%@ hookHits=%lu newReceivers=%lu controlActions=0 radioWrites=0 targetFileWrites=0",
                   success ? @"success" : @"failure",
                   (unsigned long)gHookHits,
                   (unsigned long)gNewReceiverHits);
            verify = nil;
        };
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)NSEC_PER_SEC),
                       dispatch_get_main_queue(), verify);
    });
}
