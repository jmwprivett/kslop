//
//  statbar.m
//

#import "statbar.h"
#import "remote_objc.h"
#import "../TaskRop/RemoteCall.h"
#import "../LogTextView.h"

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <mach/mach_host.h>
#import <dlfcn.h>
#import <ifaddrs.h>
#import <limits.h>
#import <math.h>
#import <net/if.h>
#import <net/if_dl.h>
#import <stdio.h>
#import <string.h>
#import <time.h>
#import <unistd.h>

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;

static void *g_iokit = NULL;
static CFMutableDictionaryRef (*pIOServiceMatching)(const char *) = NULL;
static io_service_t (*pIOServiceGetMatchingService)(mach_port_t, CFDictionaryRef) = NULL;
static CFTypeRef (*pIORegistryEntryCreateCFProperty)(io_service_t, CFStringRef, CFAllocatorRef, uint32_t) = NULL;
static kern_return_t (*pIOObjectRelease)(io_object_t) = NULL;
static bool gStatBarRemoteIOKitLoaded = false;

static bool statbar_should_log_tick(void);

static bool ensure_iokit_symbols(void)
{
    if (!g_iokit) {
        g_iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY | RTLD_GLOBAL);
        if (!g_iokit) return false;
        pIOServiceMatching               = dlsym(g_iokit, "IOServiceMatching");
        pIOServiceGetMatchingService     = dlsym(g_iokit, "IOServiceGetMatchingService");
        pIORegistryEntryCreateCFProperty = dlsym(g_iokit, "IORegistryEntryCreateCFProperty");
        pIOObjectRelease                 = dlsym(g_iokit, "IOObjectRelease");
    }
    return pIOServiceMatching && pIOServiceGetMatchingService &&
           pIORegistryEntryCreateCFProperty && pIOObjectRelease;
}

static BOOL read_smart_battery_int_local(CFStringRef key, int64_t *out)
{
    if (!key || !out || !ensure_iokit_symbols()) return NO;

    io_service_t svc = pIOServiceGetMatchingService(MACH_PORT_NULL,
                                                    pIOServiceMatching("AppleSmartBattery"));
    if (svc == MACH_PORT_NULL) return NO;

    BOOL ok = NO;
    CFNumberRef prop = (CFNumberRef)pIORegistryEntryCreateCFProperty(svc,
                                                                     key,
                                                                     kCFAllocatorDefault, 0);
    if (prop) {
        int64_t raw = 0;
        if (CFGetTypeID(prop) == CFNumberGetTypeID() &&
            CFNumberGetValue(prop, kCFNumberSInt64Type, &raw)) {
            *out = raw;
            ok = YES;
        }
        CFRelease(prop);
    }
    pIOObjectRelease(svc);
    return ok;
}

static BOOL read_battery_current_ma_local(int *outMA)
{
    if (!outMA) return NO;
    CFStringRef keys[] = {
        CFSTR("InstantAmperage"),
        CFSTR("Amperage"),
        CFSTR("BatteryCurrent"),
        CFSTR("Current"),
    };
    for (NSUInteger i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        int64_t raw = 0;
        if (read_smart_battery_int_local(keys[i], &raw)) {
            if (raw > INT_MAX) raw = INT_MAX;
            if (raw < INT_MIN) raw = INT_MIN;
            *outMA = (int)raw;
            return YES;
        }
    }
    return NO;
}

static bool ensure_remote_iokit_loaded(void)
{
    if (!ensure_iokit_symbols()) return false;
    if (gStatBarRemoteIOKitLoaded) return true;

    uint64_t path = r_alloc_str("/System/Library/Frameworks/IOKit.framework/IOKit");
    if (!path) return false;
    uint64_t handle = r_dlsym_call(R_TIMEOUT, "dlopen", path, RTLD_LAZY | RTLD_GLOBAL, 0, 0, 0, 0, 0, 0);
    if (remote_call_current_success()) r_free(path);
    if (!remote_call_current_success()) return false;
    gStatBarRemoteIOKitLoaded = (handle != 0);
    return gStatBarRemoteIOKitLoaded;
}

static uint64_t open_smart_battery_remote(void)
{
    if (!ensure_remote_iokit_loaded()) return 0;

    uint64_t name = r_alloc_str("AppleSmartBattery");
    if (!name) return 0;
    uint64_t dict = do_remote_call_stable_addr(R_TIMEOUT, (uint64_t)pIOServiceMatching, "IOServiceMatching",
                                               name, 0, 0, 0, 0, 0, 0, 0);
    if (remote_call_current_success()) r_free(name);
    if (!dict || !remote_call_current_success()) return 0;

    return do_remote_call_stable_addr(R_TIMEOUT, (uint64_t)pIOServiceGetMatchingService,
                                      "IOServiceGetMatchingService",
                                      MACH_PORT_NULL, dict, 0, 0, 0, 0, 0, 0);
}

static BOOL read_smart_battery_int_remote(uint64_t svc, const char *keyName, int64_t *out)
{
    if (!svc || !keyName || !out || !remote_call_current_success()) return NO;

    BOOL ok = NO;
    uint64_t key = r_cfstr(keyName);
    if (key) {
        uint64_t prop = do_remote_call_stable_addr(R_TIMEOUT, (uint64_t)pIORegistryEntryCreateCFProperty,
                                                   "IORegistryEntryCreateCFProperty",
                                                   svc, key, 0, 0, 0, 0, 0, 0);
        if (prop) {
            uint64_t scratch = r_dlsym_call(R_TIMEOUT, "malloc", 8, 0, 0, 0, 0, 0, 0, 0);
            if (scratch && remote_call_current_success() && remote_write64(scratch, 0)) {
                uint64_t got = r_dlsym_call(R_TIMEOUT, "CFNumberGetValue", prop, 4, scratch, 0, 0, 0, 0, 0);
                if (got && remote_call_current_success()) {
                    *out = (int64_t)remote_read64(scratch);
                    ok = remote_call_current_success() ? YES : NO;
                }
            }
            if (scratch && remote_call_current_success()) {
                r_free(scratch);
            }
            if (remote_call_current_success()) {
                r_dlsym_call(R_TIMEOUT, "CFRelease", prop, 0, 0, 0, 0, 0, 0, 0);
            }
        }
        if (remote_call_current_success()) {
            r_dlsym_call(R_TIMEOUT, "CFRelease", key, 0, 0, 0, 0, 0, 0, 0);
        }
    }

    return ok && remote_call_current_success();
}

static BOOL read_battery_current_ma_remote(int *outMA)
{
    if (!outMA || !ensure_remote_iokit_loaded()) return NO;
    const char *keys[] = {
        "InstantAmperage",
        "Amperage",
        "BatteryCurrent",
        "Current",
    };

    uint64_t svc = open_smart_battery_remote();
    if (!svc || !remote_call_current_success()) return NO;

    BOOL found = NO;
    int valueMA = 0;
    for (NSUInteger i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        int64_t raw = 0;
        if (read_smart_battery_int_remote(svc, keys[i], &raw)) {
            if (raw > INT_MAX) raw = INT_MAX;
            if (raw < INT_MIN) raw = INT_MIN;
            valueMA = (int)raw;
            found = YES;
            break;
        }
        if (!remote_call_current_success()) break;
    }

    if (remote_call_current_success()) {
        do_remote_call_stable_addr(R_TIMEOUT, (uint64_t)pIOObjectRelease, "IOObjectRelease",
                                   svc, 0, 0, 0, 0, 0, 0, 0);
    }
    if (found) *outMA = valueMA;
    return found && remote_call_current_success();
}

static BOOL read_battery_current_ma(int *outMA)
{
    static int cachedMA = 0;
    static BOOL hasCachedMA = NO;
    static time_t lastCurrentRead = 0;
    static time_t lastRemoteRead = 0;

    time_t now = time(NULL);
    if (hasCachedMA && lastCurrentRead != 0 && now >= lastCurrentRead && (now - lastCurrentRead) < 30) {
        if (outMA) *outMA = cachedMA;
        return YES;
    }
    lastCurrentRead = now;

    int localMA = 0;
    if (read_battery_current_ma_local(&localMA)) {
        cachedMA = localMA;
        hasCachedMA = YES;
        if (outMA) *outMA = cachedMA;
        if (statbar_should_log_tick())
            printf("[STATBAR] current source: local IOKit value=%dmA\n", cachedMA);
        return YES;
    }

    if (hasCachedMA && lastRemoteRead != 0 && now >= lastRemoteRead && (now - lastRemoteRead) < 60) {
        if (outMA) *outMA = cachedMA;
        return YES;
    }

    lastRemoteRead = now;
    if (statbar_should_log_tick())
        printf("[STATBAR] current source: throttled SpringBoard IOKit\n");
    int remoteMA = 0;
    if (read_battery_current_ma_remote(&remoteMA)) {
        cachedMA = remoteMA;
        hasCachedMA = YES;
        if (outMA) *outMA = cachedMA;
        return YES;
    } else if (statbar_should_log_tick()) {
        printf("[STATBAR] remote IOKit current unavailable\n");
    }
    return hasCachedMA;
}

static NSString *format_battery_current(void)
{
    int ma = 0;
    if (!read_battery_current_ma(&ma)) return nil;
    if (ma > 0) return [NSString stringWithFormat:@"+%dmA", ma];
    return [NSString stringWithFormat:@"%dmA", ma];
}

static double read_free_ram_gb(void)
{
    mach_port_t host = mach_host_self();
    vm_statistics64_data_t stat;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    kern_return_t kr = host_statistics64(host, HOST_VM_INFO64,
                                         (host_info64_t)&stat, &count);
    mach_port_deallocate(mach_task_self(), host);
    if (kr != KERN_SUCCESS) return -1.0;
    uint64_t bytes = (uint64_t)stat.free_count * (uint64_t)vm_kernel_page_size;
    return (double)bytes / (1024.0 * 1024.0 * 1024.0);
}

// System-wide CPU busy %, diffed against the previous sample. Returns -1.0
// until the second call, since a single tick sample has no baseline. Mirrors
// the static-state pattern used by read_net_speed_kbps().
static double read_cpu_percent(void)
{
    static bool havePrev = false;
    static natural_t prevTicks[CPU_STATE_MAX] = {0};

    mach_port_t host = mach_host_self();
    host_cpu_load_info_data_t info;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    kern_return_t kr = host_statistics(host, HOST_CPU_LOAD_INFO,
                                       (host_info_t)&info, &count);
    mach_port_deallocate(mach_task_self(), host);
    if (kr != KERN_SUCCESS) return -1.0;

    if (!havePrev) {
        memcpy(prevTicks, info.cpu_ticks, sizeof(prevTicks));
        havePrev = true;
        return -1.0;
    }

    natural_t dUser = info.cpu_ticks[CPU_STATE_USER]   - prevTicks[CPU_STATE_USER];
    natural_t dSys  = info.cpu_ticks[CPU_STATE_SYSTEM] - prevTicks[CPU_STATE_SYSTEM];
    natural_t dIdle = info.cpu_ticks[CPU_STATE_IDLE]   - prevTicks[CPU_STATE_IDLE];
    natural_t dNice = info.cpu_ticks[CPU_STATE_NICE]   - prevTicks[CPU_STATE_NICE];
    memcpy(prevTicks, info.cpu_ticks, sizeof(prevTicks));

    uint64_t busy  = (uint64_t)dUser + (uint64_t)dSys + (uint64_t)dNice;
    uint64_t total = busy + (uint64_t)dIdle;
    if (total == 0) return -1.0;
    double pct = 100.0 * (double)busy / (double)total;
    if (pct < 0.0) pct = 0.0;
    if (pct > 100.0) pct = 100.0;
    return pct;
}

static NSString *pad_left_visual(NSString *s, NSUInteger width)
{
    if (!s) s = @"";
    NSUInteger len = s.length;
    if (len >= width) return s;

    NSMutableString *out = [NSMutableString stringWithCapacity:width];
    for (NSUInteger i = len; i < width; i++) {
        [out appendString:@"\u2007"];
    }
    [out appendString:s];
    return out;
}

static bool read_net_totals(uint64_t *ibytes, uint64_t *obytes)
{
    if (!ibytes || !obytes) return false;
    *ibytes = 0;
    *obytes = 0;

    struct ifaddrs *head = NULL;
    if (getifaddrs(&head) != 0) return false;

    for (struct ifaddrs *ifa = head; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_data || !ifa->ifa_name) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
        if (strncmp(ifa->ifa_name, "lo", 2) == 0) continue;

        const struct if_data *data = (const struct if_data *)ifa->ifa_data;
        *ibytes += (uint64_t)data->ifi_ibytes;
        *obytes += (uint64_t)data->ifi_obytes;
    }

    freeifaddrs(head);
    return true;
}

static double statbar_now_seconds(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0.0;
    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static void read_net_speed_kbps(double *downKB, double *upKB)
{
    static bool havePrev = false;
    static uint64_t prevIn = 0;
    static uint64_t prevOut = 0;
    static double prevTime = 0.0;

    if (downKB) *downKB = 0.0;
    if (upKB) *upKB = 0.0;

    uint64_t totalIn = 0;
    uint64_t totalOut = 0;
    double now = statbar_now_seconds();
    if (now <= 0.0 || !read_net_totals(&totalIn, &totalOut)) return;

    if (havePrev && now > prevTime) {
        uint64_t din = (totalIn >= prevIn) ? (totalIn - prevIn) : 0;
        uint64_t dout = (totalOut >= prevOut) ? (totalOut - prevOut) : 0;
        double dt = now - prevTime;
        if (downKB) *downKB = ((double)din / dt) / 1024.0;
        if (upKB) *upKB = ((double)dout / dt) / 1024.0;
    }

    prevIn = totalIn;
    prevOut = totalOut;
    prevTime = now;
    havePrev = true;
}

static NSString *format_net_slot(double kbValue)
{
    if (!isfinite(kbValue) || kbValue < 0.0) kbValue = 0.0;
    NSString *token = (kbValue < 1024.0)
        ? [NSString stringWithFormat:@"%lldKB", (long long)llround(kbValue)]
        : [NSString stringWithFormat:@"%lldMB", (long long)llround(kbValue / 1024.0)];
    return pad_left_visual(token, 6);
}

static NSString *build_text(bool celsius, bool showNet, bool showCPU, bool showLabels, bool networkOnly)
{
    (void)celsius;
    NSMutableArray<NSString *> *parts = [NSMutableArray array];

    // Slot order: current -> cpu -> ram -> net. `showNet` controls whether the
    // wider (260+) layout is used; in that mode, numbers are visually padded
    // to keep columns aligned as digits change.
    if (!networkOnly) {
        NSString *current = format_battery_current();
        if (current.length) {
            NSString *display = showNet ? pad_left_visual(current, 7) : current;
            [parts addObject:display];
        } else if (statbar_should_log_tick()) {
            printf("[STATBAR] current unavailable this tick\n");
        }
    }
    if (!networkOnly && showCPU) {
        double pct = read_cpu_percent();
        NSString *num = (pct >= 0.0)
            ? [NSString stringWithFormat:@"%.0f", pct]
            : @"--";
        NSString *displayNum = showNet ? pad_left_visual(num, 3) : num;
        [parts addObject:[NSString stringWithFormat:@"%@%%%@", displayNum,
                          showLabels ? @" CPU" : @""]];
    }
    if (!networkOnly) {
        double freeGB = read_free_ram_gb();
        if (freeGB > 0) {
            NSString *suffix = showLabels ? @" RAM" : @"";
            if (freeGB < 1.0) {
                NSString *num = [NSString stringWithFormat:@"%.2f", freeGB * 1024.0];
                NSString *displayNum = showNet ? pad_left_visual(num, 6) : num;
                [parts addObject:[NSString stringWithFormat:@"%@MB%@", displayNum, suffix]];
            } else {
                NSString *num = [NSString stringWithFormat:@"%.2f", freeGB];
                NSString *displayNum = showNet ? pad_left_visual(num, 6) : num;
                [parts addObject:[NSString stringWithFormat:@"%@GB%@", displayNum, suffix]];
            }
        }
    }
    if (showNet) {
        double downKB = 0.0;
        double upKB = 0.0;
        read_net_speed_kbps(&downKB, &upKB);
        [parts addObject:[NSString stringWithFormat:@"\u2193%@ \u2191%@",
                          format_net_slot(downKB), format_net_slot(upKB)]];
    }
    if (parts.count == 0) return @"n/a";
    return [parts componentsJoinedByString:@" | "];
}

typedef struct {
    double x;
    double y;
    double width;
    double height;
} RCGRect64;

typedef struct {
    double screenWidth;
    double screenHeight;
    double topAreaHeight;
} StatBarLayoutMetrics;

static const uint64_t kStatBarOverlayTag = 99421;
static const double kStatBarFallbackScreenWidth = 390.0;
static const double kStatBarWinH = 18.0;
static const double kStatBarFontPt = 11.5;
static const double kStatBarScreenSideMargin = 8.0;
static const double kStatBarDynamicIslandExtraY = 3.0;
static const double kStatBarWinLevel = 999999.0;
static const double kStatBarLayoutValidationIntervalSec = 60.0;
static const size_t kStatBarRemoteTextBufferSize = 512;
static const int kStatBarRemoteTimeoutFloorMS = 1500;
static uint64_t gStatBarApplyTick = 0;
static bool gStatBarOverlayConfigured = false;
static bool gStatBarOverlayLastShowNet = false;
static bool gStatBarOverlayLastShowCPU = false;
static bool gStatBarOverlayLastShowLabels = false;
static double gStatBarOverlayLastX = -1.0;
static double gStatBarOverlayLastY = -1.0;
static double gStatBarOverlayLastW = -1.0;
static double gStatBarOverlayLastH = -1.0;
static uint64_t gStatBarOverlayWindow = 0;
static uint64_t gStatBarOverlayLabel = 0;
static uint64_t gStatBarSetTextSel = 0;
static uint64_t gStatBarPerformMainSel = 0;
static uint64_t gStatBarNSStringClass = 0;
static uint64_t gStatBarAllocSel = 0;
static uint64_t gStatBarInitUTF8Sel = 0;
static uint64_t gStatBarRemoteTextBuffer = 0;
static char     gStatBarLastText[256] = {0};
static char     gStatBarLastFailureReason[64] = {0};
static double   gStatBarLastLayoutValidationTime = 0.0;
static double   gStatBarLastLocalScreenWidth = -1.0;
static double   gStatBarLastLocalScreenHeight = -1.0;
static uint64_t gStatBarTextChangeCount = 0;
static uint64_t gStatBarLayoutValidationCount = 0;
static uint64_t gStatBarLayoutChangeCount = 0;
static uint64_t gStatBarRecreateCount = 0;
static uint64_t gStatBarFailureCount = 0;

static void statbar_clear_cached_layout(void);
static void statbar_clear_overlay_cache(void);

static void statbar_release_remote_text_buffer(void)
{
    if (gStatBarRemoteTextBuffer && remote_call_current_success()) {
        r_free(gStatBarRemoteTextBuffer);
    }
    gStatBarRemoteTextBuffer = 0;
}

static bool statbar_should_log_tick(void)
{
    // One-shot per session: log the first tick so the user sees the
    // overlay path took off, then never again. Heartbeats are noise.
    return gStatBarApplyTick == 1;
}

static unsigned long long statbar_elapsed_ms_since(double start)
{
    double now = statbar_now_seconds();
    if (start <= 0.0 || now <= start) return 0;
    return (unsigned long long)llround((now - start) * 1000.0);
}

static void statbar_note_failure(const char *reason)
{
    gStatBarFailureCount++;
    if (!reason || !reason[0]) reason = "unknown";
    snprintf(gStatBarLastFailureReason, sizeof(gStatBarLastFailureReason), "%s", reason);
}

bool statbar_stop_in_session(void)
{
    uint32_t oldSettleUS = r_settle_us(0);
    int oldTimeoutFloorMS =
        remote_call_set_stable_timeout_floor_ms(kStatBarRemoteTimeoutFloorMS);
    bool ok = false;

    if (!remote_call_current_success()) goto done;

    uint64_t UIApplication = r_class("UIApplication");
    if (!r_is_objc_ptr(UIApplication) || !remote_call_current_success()) goto done;

    uint64_t app = r_msg2_main(UIApplication, "sharedApplication", 0, 0, 0, 0);
    if (!r_is_objc_ptr(app) || !remote_call_current_success()) goto done;

    uint64_t assocKey = r_sel("darkswordStatBarOverlayWindow");
    if (!assocKey || !remote_call_current_success()) goto done;

    uint64_t win = r_dlsym_call(R_TIMEOUT, "objc_getAssociatedObject",
                                app, assocKey, 0, 0, 0, 0, 0, 0);
    if (!remote_call_current_success()) goto done;
    if (r_is_objc_ptr(win)) {
        r_msg2_main(win, "setHidden:", 1, 0, 0, 0);
        if (!remote_call_current_success()) goto done;
        r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, assocKey, 0, 1, 0, 0, 0, 0);
        if (!remote_call_current_success()) goto done;
    }

    statbar_release_remote_text_buffer();
    if (!remote_call_current_success()) goto done;
    statbar_clear_overlay_cache();
    printf("[STATBAR] overlay: stopped\n");
    ok = true;

done:
    if (!ok) {
        gStatBarRemoteTextBuffer = 0;
        statbar_clear_overlay_cache();
    }
    remote_call_set_stable_timeout_floor_ms(oldTimeoutFloorMS);
    r_settle_us(oldSettleUS);
    return ok;
}

void statbar_forget_remote_state(void)
{
    statbar_clear_overlay_cache();
    gStatBarSetTextSel = 0;
    gStatBarPerformMainSel = 0;
    gStatBarNSStringClass = 0;
    gStatBarAllocSel = 0;
    gStatBarInitUTF8Sel = 0;
    gStatBarRemoteTextBuffer = 0;
    gStatBarRemoteIOKitLoaded = false;
    gStatBarApplyTick = 0;
    gStatBarTextChangeCount = 0;
    gStatBarLayoutValidationCount = 0;
    gStatBarLayoutChangeCount = 0;
    gStatBarRecreateCount = 0;
    gStatBarFailureCount = 0;
    gStatBarLastFailureReason[0] = '\0';
    printf("[STATBAR] forgot remote overlay state\n");
}

static double statbar_overlay_width(bool showNet, bool showCPU, bool showLabels)
{
    double base = showNet ? 260.0 : 140.0;
    if (showCPU) base += 50.0;
    if (showLabels) {
        // Each appended " CPU" / " RAM" token adds visible width.
        base += showCPU ? 70.0 : 35.0;
    }
    return base;
}

static bool statbar_set_text_fast(uint64_t label, uint64_t textObj)
{
    if (!r_is_objc_ptr(label) || !r_is_objc_ptr(textObj)) return false;
    if (!gStatBarSetTextSel) gStatBarSetTextSel = r_sel("setText:");
    if (!gStatBarPerformMainSel) {
        gStatBarPerformMainSel = r_sel("performSelectorOnMainThread:withObject:waitUntilDone:");
    }
    if (!gStatBarSetTextSel || !gStatBarPerformMainSel) return false;
    r_msg(label, gStatBarPerformMainSel, gStatBarSetTextSel, textObj, 1, 0);
    return remote_call_current_success();
}

static void statbar_release_remote_obj(uint64_t obj)
{
    if (!r_is_objc_ptr(obj) || !remote_call_current_success()) return;
    r_dlsym_call(R_TIMEOUT, "CFRelease", obj, 0, 0, 0, 0, 0, 0, 0);
}

static uint64_t statbar_remote_autorelease_pool_push(void)
{
    return r_dlsym_call(R_TIMEOUT, "objc_autoreleasePoolPush", 0, 0, 0, 0, 0, 0, 0, 0);
}

static void statbar_remote_autorelease_pool_pop(uint64_t token)
{
    if (!token || !remote_call_current_success()) return;
    r_dlsym_call(R_TIMEOUT, "objc_autoreleasePoolPop", token, 0, 0, 0, 0, 0, 0, 0);
}

static bool statbar_valid_screen_length(double v)
{
    return isfinite(v) && v >= 100.0 && v <= 2000.0;
}

static bool statbar_valid_top_area(double v)
{
    return isfinite(v) && v >= 10.0 && v <= 120.0;
}

static bool statbar_layout_value_equal(double a, double b)
{
    return fabs(a - b) < 0.5;
}

static bool statbar_layout_is_cached(bool showNet, bool showCPU, bool showLabels,
                                     double x, double y, double width, double height)
{
    return gStatBarOverlayConfigured &&
           gStatBarOverlayLastShowNet == showNet &&
           gStatBarOverlayLastShowCPU == showCPU &&
           gStatBarOverlayLastShowLabels == showLabels &&
           statbar_layout_value_equal(gStatBarOverlayLastX, x) &&
           statbar_layout_value_equal(gStatBarOverlayLastY, y) &&
           statbar_layout_value_equal(gStatBarOverlayLastW, width) &&
           statbar_layout_value_equal(gStatBarOverlayLastH, height);
}

static void statbar_mark_layout_cached(bool showNet, bool showCPU, bool showLabels,
                                       double x, double y, double width, double height)
{
    if (!statbar_layout_is_cached(showNet, showCPU, showLabels, x, y, width, height)) {
        gStatBarLayoutChangeCount++;
    }
    gStatBarOverlayConfigured = true;
    gStatBarOverlayLastShowNet = showNet;
    gStatBarOverlayLastShowCPU = showCPU;
    gStatBarOverlayLastShowLabels = showLabels;
    gStatBarOverlayLastX = x;
    gStatBarOverlayLastY = y;
    gStatBarOverlayLastW = width;
    gStatBarOverlayLastH = height;
}

static void statbar_record_layout_validation(void)
{
    CGRect bounds = UIScreen.mainScreen.bounds;
    double width = fabs(bounds.size.width);
    double height = fabs(bounds.size.height);
    if (statbar_valid_screen_length(width)) gStatBarLastLocalScreenWidth = width;
    if (statbar_valid_screen_length(height)) gStatBarLastLocalScreenHeight = height;
    gStatBarLastLayoutValidationTime = statbar_now_seconds();
    gStatBarLayoutValidationCount++;
}

static void statbar_clear_cached_layout(void)
{
    gStatBarOverlayConfigured = false;
    gStatBarOverlayLastShowNet = false;
    gStatBarOverlayLastShowCPU = false;
    gStatBarOverlayLastShowLabels = false;
    gStatBarOverlayLastX = -1.0;
    gStatBarOverlayLastY = -1.0;
    gStatBarOverlayLastW = -1.0;
    gStatBarOverlayLastH = -1.0;
    gStatBarLastLayoutValidationTime = 0.0;
    gStatBarLastLocalScreenWidth = -1.0;
    gStatBarLastLocalScreenHeight = -1.0;
}

static void statbar_clear_overlay_cache(void)
{
    gStatBarOverlayWindow = 0;
    gStatBarOverlayLabel = 0;
    gStatBarLastText[0] = '\0';
    statbar_clear_cached_layout();
}

static bool statbar_last_text_matches(const char *text)
{
    if (!text) text = "";
    return gStatBarLastText[0] != '\0' &&
           strcmp(gStatBarLastText, text) == 0;
}

static void statbar_remember_last_text(const char *text)
{
    if (!text) text = "";
    if (!statbar_last_text_matches(text)) gStatBarTextChangeCount++;
    snprintf(gStatBarLastText, sizeof(gStatBarLastText), "%s", text);
}

static bool statbar_cached_layout_flags_match(bool showNet, bool showCPU, bool showLabels)
{
    return gStatBarOverlayConfigured &&
           gStatBarOverlayLastShowNet == showNet &&
           gStatBarOverlayLastShowCPU == showCPU &&
           gStatBarOverlayLastShowLabels == showLabels;
}

static bool statbar_layout_validation_due(bool showNet, bool showCPU, bool showLabels)
{
    if (!statbar_cached_layout_flags_match(showNet, showCPU, showLabels)) return true;

    CGRect bounds = UIScreen.mainScreen.bounds;
    double width = fabs(bounds.size.width);
    double height = fabs(bounds.size.height);
    if ((statbar_valid_screen_length(width) &&
         !statbar_layout_value_equal(width, gStatBarLastLocalScreenWidth)) ||
        (statbar_valid_screen_length(height) &&
         !statbar_layout_value_equal(height, gStatBarLastLocalScreenHeight))) {
        return true;
    }

    double now = statbar_now_seconds();
    return gStatBarLastLayoutValidationTime <= 0.0 ||
           now <= 0.0 ||
           now < gStatBarLastLayoutValidationTime ||
           (now - gStatBarLastLayoutValidationTime) >= kStatBarLayoutValidationIntervalSec;
}

static double statbar_fallback_top_area_for_screen(double screenWidth, double screenHeight)
{
    double shortSide = fmin(screenWidth, screenHeight);
    double longSide = fmax(screenWidth, screenHeight);
    if (!statbar_valid_screen_length(shortSide) || !statbar_valid_screen_length(longSide)) {
        return 20.0;
    }

    if (longSide >= 852.0 && shortSide >= 390.0) return 59.0;
    if (longSide >= 844.0 && shortSide >= 390.0) return 47.0;
    if (longSide >= 812.0 && shortSide >= 375.0) return 44.0;
    return 20.0;
}

static uint64_t statbar_read_springboard_interface_orientation(uint64_t win)
{
    if (!r_is_objc_ptr(win)) return 0;
    uint64_t scene = r_msg2_main(win, "windowScene", 0, 0, 0, 0);
    if (!r_is_objc_ptr(scene)) return 0;
    return r_msg2_main(scene, "interfaceOrientation", 0, 0, 0, 0);
}

static StatBarLayoutMetrics statbar_read_layout_metrics(uint64_t win)
{
    StatBarLayoutMetrics m = { kStatBarFallbackScreenWidth, 0.0, 0.0 };

    CGRect bounds = UIScreen.mainScreen.bounds;
    double w = bounds.size.width;
    double h = bounds.size.height;
    bool readRemoteBounds = false;

    if (r_is_objc_ptr(win)) {
        RCGRect64 remoteBounds = {0};
        if (r_msg2_main_struct_ret(win, "bounds",
                                   &remoteBounds, sizeof(remoteBounds),
                                   NULL, 0, NULL, 0, NULL, 0, NULL, 0)) {
            double rw = fabs(remoteBounds.width);
            double rh = fabs(remoteBounds.height);
            if (statbar_valid_screen_length(rw) && statbar_valid_screen_length(rh)) {
                w = rw;
                h = rh;
                readRemoteBounds = true;
            }
        }
    }

    uint64_t orientation = 0;
    bool landscape = false;
    if (!readRemoteBounds) {
        orientation = r_is_objc_ptr(win)
            ? statbar_read_springboard_interface_orientation(win) : 0;
        landscape = (orientation == 3 || orientation == 4);
    }
    if (!readRemoteBounds && landscape) {
        w = fmax(bounds.size.width, bounds.size.height);
        h = fmin(bounds.size.width, bounds.size.height);
    }

    if (statbar_valid_screen_length(w)) m.screenWidth = w;
    if (statbar_valid_screen_length(h)) m.screenHeight = h;

    m.topAreaHeight = statbar_fallback_top_area_for_screen(m.screenWidth, m.screenHeight);
    return m;
}

static double statbar_overlay_y_for_top_area(double topAreaHeight)
{
    if (!statbar_valid_top_area(topAreaHeight)) topAreaHeight = 20.0;

    if (topAreaHeight >= 36.0) {
        double y = topAreaHeight - (kStatBarWinH / 2.0);
        if (topAreaHeight >= 55.0) y += kStatBarDynamicIslandExtraY;
        return fmax(1.0, floor(y));
    }
    return fmax(1.0, floor((topAreaHeight - kStatBarWinH) / 2.0));
}

static uint64_t statbar_nsstring_utf8_fast(const char *cstr)
{
    if (!cstr) cstr = "n/a";
    if (strlen(cstr) + 1 > kStatBarRemoteTextBufferSize) return 0;
    if (!gStatBarRemoteTextBuffer) {
        gStatBarRemoteTextBuffer =
            r_dlsym_call(R_TIMEOUT, "malloc", kStatBarRemoteTextBufferSize, 0, 0, 0, 0, 0, 0, 0);
    }
    if (!gStatBarRemoteTextBuffer ||
        !remote_call_current_success() ||
        !remote_writeStr(gStatBarRemoteTextBuffer, cstr)) {
        return 0;
    }
    if (!gStatBarNSStringClass) gStatBarNSStringClass = r_class("NSString");
    if (!gStatBarAllocSel) gStatBarAllocSel = r_sel("alloc");
    if (!gStatBarInitUTF8Sel) gStatBarInitUTF8Sel = r_sel("initWithUTF8String:");
    if (!r_is_objc_ptr(gStatBarNSStringClass) || !gStatBarAllocSel || !gStatBarInitUTF8Sel) {
        return 0;
    }
    uint64_t allocated = r_msg(gStatBarNSStringClass, gStatBarAllocSel, 0, 0, 0, 0);
    uint64_t ns = r_is_objc_ptr(allocated)
        ? r_msg(allocated, gStatBarInitUTF8Sel, gStatBarRemoteTextBuffer, 0, 0, 0)
        : 0;
    return ns;
}

static bool r_send_double_main(uint64_t obj, const char *selName, double value)
{
    if (!r_is_objc_ptr(obj)) return false;
    r_msg2_main_raw(obj, selName,
                    &value, sizeof(value),
                    NULL, 0,
                    NULL, 0,
                    NULL, 0);
    return remote_call_current_success();
}

static bool r_send_rect_main(uint64_t obj, const char *selName,
                             double x, double y, double width, double height)
{
    if (!r_is_objc_ptr(obj)) return false;
    RCGRect64 rect = { x, y, width, height };
    r_msg2_main_raw(obj, selName,
                    &rect, sizeof(rect),
                    NULL, 0,
                    NULL, 0,
                    NULL, 0);
    return remote_call_current_success();
}

static uint64_t statbar_overlay_font(void)
{
    uint64_t UIFont = r_class("UIFont");
    if (!r_is_objc_ptr(UIFont)) return 0;

    double size = kStatBarFontPt;
    double weight = 0.0;
    uint64_t font = r_msg2_main_raw(UIFont, "monospacedDigitSystemFontOfSize:weight:",
                                    &size, sizeof(size),
                                    &weight, sizeof(weight),
                                    NULL, 0,
                                    NULL, 0);
    if (r_is_objc_ptr(font)) return font;
    if (!remote_call_current_success()) return 0;

    return r_msg2_main_raw(UIFont, "systemFontOfSize:",
                           &size, sizeof(size),
                           NULL, 0,
                           NULL, 0,
                           NULL, 0);
}

static bool statbar_apply_overlay_style(uint64_t label)
{
    if (!r_is_objc_ptr(label)) return false;

    uint64_t font = statbar_overlay_font();
    if (!remote_call_current_success()) return false;
    if (r_is_objc_ptr(font)) {
        r_msg2_main(label, "setFont:", font, 0, 0, 0);
        if (!remote_call_current_success()) return false;
    }

    uint64_t layer = r_msg2_main(label, "layer", 0, 0, 0, 0);
    if (!remote_call_current_success()) return false;
    if (r_is_objc_ptr(layer)) {
        double radius = kStatBarWinH / 2.0;
        if (!r_send_double_main(layer, "setCornerRadius:", radius)) return false;
        r_msg2_main(layer, "setMasksToBounds:", 1, 0, 0, 0);
        if (!remote_call_current_success()) return false;
    }
    return true;
}

static bool statbar_apply_overlay_layout(uint64_t win, uint64_t label,
                                         bool showNet, bool showCPU, bool showLabels)
{
    if (!r_is_objc_ptr(win)) {
        statbar_note_failure("layout-window");
        return false;
    }

    StatBarLayoutMetrics metrics = statbar_read_layout_metrics(win);
    if (!remote_call_current_success()) {
        statbar_note_failure("layout-metrics");
        return false;
    }
    statbar_record_layout_validation();
    double screenWidth = statbar_valid_screen_length(metrics.screenWidth) ?
                         metrics.screenWidth : kStatBarFallbackScreenWidth;
    double maxWidth = fmax(1.0, screenWidth - (kStatBarScreenSideMargin * 2.0));
    double width = fmin(statbar_overlay_width(showNet, showCPU, showLabels), maxWidth);
    double x = floor((screenWidth - width) / 2.0);
    if (x < 0.0) x = 0.0;
    double y = statbar_overlay_y_for_top_area(metrics.topAreaHeight);

    if (statbar_should_log_tick()) {
        printf("[STATBAR] overlay: layout screen=%.1fx%.1f topArea=%.1f frame={%.1f,%.1f,%.1f,%.1f}\n",
               screenWidth, metrics.screenHeight, metrics.topAreaHeight, x, y, width, kStatBarWinH);
    }

    if (statbar_layout_is_cached(showNet, showCPU, showLabels, x, y, width, kStatBarWinH)) {
        return true;
    }

    bool ok = r_send_rect_main(win, "setFrame:", x, y, width, kStatBarWinH);
    if (ok) ok = r_send_double_main(win, "setWindowLevel:", kStatBarWinLevel);
    if (ok) {
        r_msg2_main(win, "setUserInteractionEnabled:", 0, 0, 0, 0);
        ok = remote_call_current_success();
    }

    if (ok && r_is_objc_ptr(label)) {
        ok = r_send_rect_main(label, "setFrame:", 0.0, 0.0, width, kStatBarWinH);
        if (ok) ok = statbar_apply_overlay_style(label);
    }
    if (ok) {
        statbar_mark_layout_cached(showNet, showCPU, showLabels, x, y, width, kStatBarWinH);
    } else {
        statbar_note_failure("layout-send");
    }
    return ok;
}

static bool statbar_install_overlay_inner(NSString *text,
                                          bool showNet,
                                          bool showCPU,
                                          bool showLabels)
{
    if (statbar_should_log_tick())
        printf("[STATBAR] overlay: entry (dedicated UIWindow)\n");

    const char *utf8 = text.UTF8String;
    if (!utf8) utf8 = "n/a";

    if (r_is_objc_ptr(gStatBarOverlayWindow) && r_is_objc_ptr(gStatBarOverlayLabel)) {
        bool textChanged = !statbar_last_text_matches(utf8);
        bool layoutDue = statbar_layout_validation_due(showNet, showCPU, showLabels);
        if (!textChanged && !layoutDue) {
            return true;
        }

        bool textOK = true;
        if (textChanged) {
            uint64_t textObj = statbar_nsstring_utf8_fast(utf8);
            if (!r_is_objc_ptr(textObj)) {
                printf("[STATBAR] overlay: NSString alloc failed\n");
                statbar_note_failure("text-alloc");
                return false;
            }
            textOK = statbar_set_text_fast(gStatBarOverlayLabel, textObj);
            statbar_release_remote_obj(textObj);
        }

        bool layoutOK = textOK && remote_call_current_success() && (!layoutDue ||
            statbar_apply_overlay_layout(gStatBarOverlayWindow,
                                         gStatBarOverlayLabel,
                                         showNet,
                                         showCPU,
                                         showLabels));
        if (textOK && layoutOK && remote_call_current_success()) {
            if (textChanged) statbar_remember_last_text(utf8);
            if (statbar_should_log_tick())
                printf("[STATBAR] overlay: fast cached text updated\n");
            return true;
        }
        if (!textOK) statbar_note_failure("set-text");
        statbar_clear_overlay_cache();
        return false;
    }

    uint64_t textObj = statbar_nsstring_utf8_fast(utf8);
    if (!r_is_objc_ptr(textObj)) {
        printf("[STATBAR] overlay: NSString alloc failed\n");
        statbar_note_failure("text-alloc");
        return false;
    }

    uint64_t UIApplication = r_class("UIApplication");
    if (!r_is_objc_ptr(UIApplication)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: UIApplication missing\n");
        statbar_note_failure("uiapplication");
        return false;
    }

    uint64_t app = r_msg2_main(UIApplication, "sharedApplication", 0, 0, 0, 0);
    if (!r_is_objc_ptr(app)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: sharedApplication nil\n");
        statbar_note_failure("shared-application");
        return false;
    }

    uint64_t assocKey = r_sel("darkswordStatBarOverlayWindow");
    if (!assocKey) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: assoc key failed\n");
        statbar_note_failure("assoc-key");
        return false;
    }

    uint64_t cachedWin = r_dlsym_call(R_TIMEOUT, "objc_getAssociatedObject",
                                      app, assocKey, 0, 0, 0, 0, 0, 0);
    if (!remote_call_current_success()) {
        statbar_note_failure("associated-window");
        return false;
    }
    if (r_is_objc_ptr(cachedWin)) {
        uint64_t cachedLabel = r_msg2_main(cachedWin, "viewWithTag:", kStatBarOverlayTag, 0, 0, 0);
        if (!remote_call_current_success()) {
            statbar_note_failure("associated-label");
            statbar_clear_overlay_cache();
            return false;
        }
        if (statbar_should_log_tick())
            printf("[STATBAR] overlay: cached window=0x%llx label=0x%llx\n", cachedWin, cachedLabel);
        if (r_is_objc_ptr(cachedLabel)) {
            gStatBarOverlayWindow = cachedWin;
            gStatBarOverlayLabel = cachedLabel;
            bool textOK = statbar_set_text_fast(cachedLabel, textObj);
            bool layoutOK = textOK && remote_call_current_success() &&
                statbar_apply_overlay_layout(cachedWin,
                                             cachedLabel,
                                             showNet,
                                             showCPU,
                                             showLabels);
            bool showOK = false;
            if (layoutOK && remote_call_current_success()) {
                r_msg2_main(cachedWin, "setHidden:", 0, 0, 0, 0);
                showOK = remote_call_current_success();
            }
            statbar_release_remote_obj(textObj);
            if (textOK && layoutOK && showOK && remote_call_current_success()) {
                statbar_remember_last_text(utf8);
                if (statbar_should_log_tick())
                    printf("[STATBAR] overlay: cached text updated\n");
                return true;
            }
            if (!textOK) statbar_note_failure("cached-set-text");
            if (!showOK) statbar_note_failure("cached-show");
            statbar_clear_overlay_cache();
            return false;
        }
        r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, assocKey, 0, 1, 0, 0, 0, 0);
        if (!remote_call_current_success()) {
            statbar_note_failure("associated-clear");
            statbar_clear_overlay_cache();
            return false;
        }
        statbar_clear_overlay_cache();
    }

    uint64_t keyWin = r_msg2_main(app, "keyWindow", 0, 0, 0, 0);
    if (!remote_call_current_success()) {
        statbar_note_failure("key-window-call");
        return false;
    }
    if (!r_is_objc_ptr(keyWin)) {
        uint64_t windows = r_msg2_main(app, "windows", 0, 0, 0, 0);
        if (remote_call_current_success()) {
            uint64_t count = r_is_objc_ptr(windows)
                ? r_msg2_main(windows, "count", 0, 0, 0, 0)
                : 0;
            if (remote_call_current_success() && count > 0 && count < 64) {
                keyWin = r_msg2_main(windows, "objectAtIndex:", 0, 0, 0, 0);
            }
        }
    }
    if (!r_is_objc_ptr(keyWin)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: keyWindow nil\n");
        statbar_note_failure("key-window");
        return false;
    }

    uint64_t scene = r_msg2_main(keyWin, "windowScene", 0, 0, 0, 0);
    if (!r_is_objc_ptr(scene)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: windowScene nil\n");
        statbar_note_failure("window-scene");
        return false;
    }

    uint64_t UIWindow = r_class("UIWindow");
    if (!r_is_objc_ptr(UIWindow)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: UIWindow missing\n");
        statbar_note_failure("uiwindow");
        return false;
    }

    uint64_t winAlloc = r_msg2_main(UIWindow, "alloc", 0, 0, 0, 0);
    if (!r_is_objc_ptr(winAlloc)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: UIWindow alloc failed\n");
        statbar_note_failure("window-alloc");
        return false;
    }

    uint64_t win = r_msg2_main(winAlloc, "initWithWindowScene:", scene, 0, 0, 0);
    if (!r_is_objc_ptr(win)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: initWithWindowScene failed\n");
        statbar_note_failure("window-init");
        return false;
    }
    if (statbar_should_log_tick())
        printf("[STATBAR] overlay: window=0x%llx\n", win);

    uint64_t UIColor = r_class("UIColor");
    if (r_is_objc_ptr(UIColor)) {
        uint64_t clear = r_msg2_main(UIColor, "clearColor", 0, 0, 0, 0);
        if (remote_call_current_success() && r_is_objc_ptr(clear)) {
            r_msg2_main(win, "setBackgroundColor:", clear, 0, 0, 0);
        }
    }
    if (!remote_call_current_success()) {
        statbar_note_failure("window-config");
        statbar_release_remote_obj(textObj);
        return false;
    }

    uint64_t UILabel = r_class("UILabel");
    if (!r_is_objc_ptr(UILabel)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: UILabel missing\n");
        statbar_note_failure("uilabel");
        return false;
    }

    uint64_t labelAlloc = r_msg2_main(UILabel, "alloc", 0, 0, 0, 0);
    if (!r_is_objc_ptr(labelAlloc)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: UILabel alloc failed\n");
        statbar_note_failure("label-alloc");
        return false;
    }

    uint64_t label = r_msg2_main(labelAlloc, "init", 0, 0, 0, 0);
    if (!r_is_objc_ptr(label)) {
        statbar_release_remote_obj(textObj);
        printf("[STATBAR] overlay: UILabel init failed\n");
        statbar_note_failure("label-init");
        return false;
    }
    if (statbar_should_log_tick())
        printf("[STATBAR] overlay: label=0x%llx\n", label);

    bool configOK = true;
    r_msg2_main(label, "setText:", textObj, 0, 0, 0);
    configOK = remote_call_current_success();
    if (configOK) {
        r_msg2_main(label, "setTag:", kStatBarOverlayTag, 0, 0, 0);
        configOK = remote_call_current_success();
    }
    if (configOK) {
        r_msg2_main(label, "setTextAlignment:", 1, 0, 0, 0);
        configOK = remote_call_current_success();
    }
    if (configOK) {
        r_msg2_main(label, "setNumberOfLines:", 1, 0, 0, 0);
        configOK = remote_call_current_success();
    }

    if (configOK && r_is_objc_ptr(UIColor)) {
        uint64_t black = r_msg2_main(UIColor, "blackColor", 0, 0, 0, 0);
        configOK = remote_call_current_success();
        uint64_t white = configOK
            ? r_msg2_main(UIColor, "whiteColor", 0, 0, 0, 0)
            : 0;
        configOK = configOK && remote_call_current_success();
        if (configOK && r_is_objc_ptr(black)) {
            r_msg2_main(label, "setBackgroundColor:", black, 0, 0, 0);
            configOK = remote_call_current_success();
        }
        if (configOK && r_is_objc_ptr(white)) {
            r_msg2_main(label, "setTextColor:", white, 0, 0, 0);
            configOK = remote_call_current_success();
        }
    }

    if (!configOK || !remote_call_current_success()) {
        statbar_note_failure("label-config");
        statbar_release_remote_obj(textObj);
        statbar_clear_overlay_cache();
        return false;
    }

    bool layoutOK = statbar_apply_overlay_layout(win, label, showNet, showCPU, showLabels);
    if (!layoutOK) {
        statbar_release_remote_obj(textObj);
        statbar_clear_overlay_cache();
        return false;
    }
    r_msg2_main(win, "addSubview:", label, 0, 0, 0);
    bool attachOK = remote_call_current_success();
    if (attachOK) {
        r_msg2_main(win, "setHidden:", 0, 0, 0, 0);
        attachOK = remote_call_current_success();
    }
    if (attachOK) {
        r_dlsym_call(R_TIMEOUT, "objc_setAssociatedObject", app, assocKey, win, 1, 0, 0, 0, 0);
        attachOK = remote_call_current_success();
    }
    statbar_release_remote_obj(textObj);
    if (!attachOK || !remote_call_current_success()) {
        statbar_note_failure("attach");
        statbar_clear_overlay_cache();
        return false;
    }

    gStatBarOverlayWindow = win;
    gStatBarOverlayLabel = label;
    gStatBarRecreateCount++;
    statbar_remember_last_text(utf8);

    if (statbar_should_log_tick())
        printf("[STATBAR] overlay: installed dedicated window\n");
    return true;
}

static bool statbar_install_overlay(NSString *text, bool showNet, bool showCPU, bool showLabels)
{
    const char *utf8 = text.UTF8String;
    if (!utf8) utf8 = "n/a";
    if (r_is_objc_ptr(gStatBarOverlayWindow) &&
        r_is_objc_ptr(gStatBarOverlayLabel) &&
        statbar_last_text_matches(utf8) &&
        !statbar_layout_validation_due(showNet, showCPU, showLabels)) {
        return true;
    }

    uint64_t pool = statbar_remote_autorelease_pool_push();
    if (!remote_call_current_success()) {
        statbar_note_failure("install-pool-push");
        statbar_clear_overlay_cache();
        return false;
    }

    bool ok = statbar_install_overlay_inner(text, showNet, showCPU, showLabels);
    if (remote_call_current_success()) {
        statbar_remote_autorelease_pool_pop(pool);
    }
    if (!remote_call_current_success()) {
        statbar_note_failure("install-pool-pop");
        statbar_clear_overlay_cache();
        return false;
    }
    return ok;
}

// Recursive walk of the SpringBoard status-bar wrapper subview tree, looking
// for STUIStatusBarStringView (iOS 17+) / _UIStatusBarStringView (iOS 16).
// Stops when the first label whose -text contains ":" is found (clock).
static uint64_t __attribute__((unused)) walk_for_clock(uint64_t view, uint64_t cls17, uint64_t cls16,
                                                       uint64_t selIsKind, uint64_t selSubviews,
                                                       uint64_t selCount, uint64_t selObjAtIdx,
                                                       uint64_t selText, uint64_t selContains,
                                                       uint64_t colonStr, int depth, int *visited)
{
    if (depth > 10) return 0;
    if (!r_is_objc_ptr(view)) return 0;
    (*visited)++;

    if (cls17) {
        usleep(20000);
        if ((r_msg(view, selIsKind, cls17, 0, 0, 0) & 0xff) != 0) goto found;
    }
    if (cls16) {
        usleep(20000);
        if ((r_msg(view, selIsKind, cls16, 0, 0, 0) & 0xff) != 0) goto found;
    }
    goto recurse;

found: {
        if (!colonStr) return view;
        usleep(20000);
        uint64_t txt = r_msg(view, selText, 0, 0, 0, 0);
        if (!r_is_objc_ptr(txt)) return view;
        usleep(20000);
        if ((r_msg(txt, selContains, colonStr, 0, 0, 0) & 0xff) != 0) return view;
        return view;
    }

recurse: {
        usleep(20000);
        uint64_t subs = r_msg(view, selSubviews, 0, 0, 0, 0);
        if (!r_is_objc_ptr(subs)) return 0;
        usleep(20000);
        uint64_t cnt = r_msg(subs, selCount, 0, 0, 0, 0);
        if (cnt == 0 || cnt > 64) return 0;
        for (uint64_t i = 0; i < cnt; i++) {
            usleep(20000);
            uint64_t sub = r_msg(subs, selObjAtIdx, i, 0, 0, 0);
            if (!r_is_objc_ptr(sub)) continue;
            uint64_t hit = walk_for_clock(sub, cls17, cls16, selIsKind, selSubviews,
                                          selCount, selObjAtIdx, selText, selContains,
                                          colonStr, depth + 1, visited);
            if (hit) {
                if (!colonStr) return hit;
                usleep(20000);
                uint64_t txt = r_msg(hit, selText, 0, 0, 0, 0);
                if (r_is_objc_ptr(txt)) {
                    usleep(20000);
                    if ((r_msg(txt, selContains, colonStr, 0, 0, 0) & 0xff) != 0) return hit;
                }
            }
        }
        return 0;
    }
}

bool statbar_apply_in_session(bool celsius, bool showNet, bool showCPU, bool showLabels, bool networkOnly)
{
    uint32_t oldSettleUS = r_settle_us(0);
    int oldTimeoutFloorMS =
        remote_call_set_stable_timeout_floor_ms(kStatBarRemoteTimeoutFloorMS);
    double start = statbar_now_seconds();
    bool ok = false;
    gStatBarLastFailureReason[0] = '\0';

    @autoreleasepool {
        gStatBarApplyTick++;
        if (!remote_call_current_success()) {
            statbar_note_failure("remote-state");
        } else {
            bool effectiveShowNet = showNet || networkOnly;
            bool effectiveShowCPU = networkOnly ? false : showCPU;
            bool effectiveShowLabels = networkOnly ? false : showLabels;
            NSString *text = build_text(celsius,
                                        effectiveShowNet,
                                        effectiveShowCPU,
                                        effectiveShowLabels,
                                        networkOnly);
            if (statbar_should_log_tick()) {
                printf("[STATBAR] === entry === text='%s' celsius=%d showNet=%d showCPU=%d showLabels=%d networkOnly=%d tick=%llu\n",
                       text.UTF8String,
                       celsius,
                       showNet,
                       showCPU,
                       showLabels,
                       networkOnly,
                       gStatBarApplyTick);
            }

            ok = statbar_install_overlay(text,
                                         effectiveShowNet,
                                         effectiveShowCPU,
                                         effectiveShowLabels);
        }
    }

    unsigned long long totalMS = statbar_elapsed_ms_since(start);
    if (!ok || totalMS > 500ULL) {
        const char *reason = ok
            ? "-"
            : (gStatBarLastFailureReason[0] ? gStatBarLastFailureReason : "unknown");
        printf("[STATBAR] apply %s tick=%llu total=%llums reason=%s textChanges=%llu layoutChecks=%llu layoutChanges=%llu recreates=%llu failures=%llu\n",
               ok ? "slow" : "failed",
               gStatBarApplyTick,
               totalMS,
               reason,
               gStatBarTextChangeCount,
               gStatBarLayoutValidationCount,
               gStatBarLayoutChangeCount,
               gStatBarRecreateCount,
               gStatBarFailureCount);
    }
    remote_call_set_stable_timeout_floor_ms(oldTimeoutFloorMS);
    r_settle_us(oldSettleUS);
    return ok;
}

bool statbar_apply(bool celsius, bool showNet, bool showCPU, bool showLabels, bool networkOnly)
{
    if (init_remote_call("SpringBoard", false) != 0) {
        printf("[STATBAR] init_remote_call(SpringBoard) failed\n");
        return false;
    }

    bool ok = statbar_apply_in_session(celsius, showNet, showCPU, showLabels, networkOnly);
    statbar_release_remote_text_buffer();
    if (remote_call_current_success()) {
        destroy_remote_call();
    } else {
        abandon_remote_call();
    }
    statbar_forget_remote_state();
    return ok;
}
