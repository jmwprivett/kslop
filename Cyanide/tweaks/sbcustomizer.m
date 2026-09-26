//
//  sbcustomizer.m
//

#import "sbcustomizer.h"
#import "remote_objc.h"
#import "../TaskRop/RemoteCall.h"
#import <pthread.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>
#import "../LogTextView.h"

#define SBC_MAX_DOCK_MOVES 7
#define SBC_MAX_ROOT_PAGES 64
#define SBC_MAX_ICONS_PER_LIST 128

typedef struct {
    uint64_t icon;
    uint64_t sourceList;
    uint64_t sourceIndex;
    uint64_t dockIndex;
    char bundleID[192];
    bool active;
} SBCDockMove;

typedef struct {
    int pid;
    uint64_t iconModel;
    uint64_t rootFolder;
    uint64_t dockList;
    uint64_t autosaveAssertion;
    bool exactRollbackRequired;
    uint64_t originalDockIcons[SBC_MAX_DOCK_MOVES];
    size_t originalDockCount;
    SBCDockMove moves[SBC_MAX_DOCK_MOVES];
    size_t moveCount;
} SBCDockRemoteState;

static SBCDockRemoteState gSBCDockState;

static bool sbc_icon_at_index(uint64_t list, uint64_t index,
                              uint64_t *iconOut);

#define SBC_METHOD_SHAPE_CACHE_CAP 96
typedef struct {
    int pid;
    uint64_t objectClass;
    uint64_t selector;
    char returnType;
    char argTypes[8];
} SBCMethodShapeCacheEntry;

static pthread_mutex_t gSBCMethodShapeCacheLock = PTHREAD_MUTEX_INITIALIZER;
static SBCMethodShapeCacheEntry
    gSBCMethodShapeCache[SBC_METHOD_SHAPE_CACHE_CAP];
static size_t gSBCMethodShapeCacheNext;

static bool sbc_method_shape_cache_lookup(int pid, uint64_t objectClass,
                                          uint64_t selector, char returnType,
                                          const char *argTypes)
{
    bool found = false;
    pthread_mutex_lock(&gSBCMethodShapeCacheLock);
    for (size_t i = 0; i < SBC_METHOD_SHAPE_CACHE_CAP; i++) {
        SBCMethodShapeCacheEntry *entry = &gSBCMethodShapeCache[i];
        if (entry->pid == pid && entry->objectClass == objectClass &&
            entry->selector == selector && entry->returnType == returnType &&
            strcmp(entry->argTypes, argTypes) == 0) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&gSBCMethodShapeCacheLock);
    return found;
}

static void sbc_method_shape_cache_store(int pid, uint64_t objectClass,
                                         uint64_t selector, char returnType,
                                         const char *argTypes)
{
    if (strlen(argTypes) >= sizeof(gSBCMethodShapeCache[0].argTypes)) return;
    pthread_mutex_lock(&gSBCMethodShapeCacheLock);
    SBCMethodShapeCacheEntry *entry =
        &gSBCMethodShapeCache[gSBCMethodShapeCacheNext];
    gSBCMethodShapeCacheNext =
        (gSBCMethodShapeCacheNext + 1) % SBC_METHOD_SHAPE_CACHE_CAP;
    memset(entry, 0, sizeof(*entry));
    entry->pid = pid;
    entry->objectClass = objectClass;
    entry->selector = selector;
    entry->returnType = returnType;
    snprintf(entry->argTypes, sizeof(entry->argTypes), "%s", argTypes);
    pthread_mutex_unlock(&gSBCMethodShapeCacheLock);
}

// Validate the invocation envelope before a private model mutation. NSInvocation
// itself consumes SpringBoard's concrete type encoding, so we only need to
// prove selector availability, argument count/widths, and concrete ABI types.
// Avoid copying encoding C strings through remote VM mappings: those strings
// live in shared-cache submaps that are not reliably readable on every build.
static bool sbc_remote_type_equals(uint64_t encodedType, char expectedType)
{
    if (!encodedType || expectedType == '\0') return false;
    char expectedString[2] = { expectedType, '\0' };
    uint64_t remoteExpected = r_alloc_str(expectedString);
    if (!remoteExpected) return false;
    uint64_t comparison = r_dlsym_call(R_TIMEOUT, "strcmp",
                                       encodedType, remoteExpected,
                                       0, 0, 0, 0, 0, 0);
    bool equal = comparison == 0 && remote_call_current_success();
    r_free(remoteExpected);
    return equal && remote_call_current_success();
}

static bool sbc_method_shape(uint64_t obj, const char *selectorName,
                             char returnType, const char *argTypes)
{
    if (!r_is_objc_ptr(obj) || !selectorName || !argTypes) return false;
    uint64_t selector = r_sel(selectorName);
    if (!selector) return false;

    int pid = remote_call_current_pid();
    uint64_t objectClass = r_dlsym_call(R_TIMEOUT, "object_getClass",
                                        obj, 0, 0, 0, 0, 0, 0, 0);
    if (!r_is_objc_ptr(objectClass)) return false;
    if (sbc_method_shape_cache_lookup(pid, objectClass, selector,
                                      returnType, argTypes)) {
        return remote_call_current_success();
    }
    if (!r_responds_main(obj, selectorName)) return false;

    uint64_t signature = r_msg2_main(obj, "methodSignatureForSelector:",
                                     selector, 0, 0, 0);
    if (!r_is_objc_ptr(signature)) return false;

    size_t userArgCount = strlen(argTypes);
    uint64_t numberOfArguments = r_msg2(signature, "numberOfArguments",
                                        0, 0, 0, 0);
    if (numberOfArguments != userArgCount + 2) return false;
    uint64_t returnLength = r_msg2(signature, "methodReturnLength",
                                   0, 0, 0, 0);
    uint64_t expectedReturnLength = returnType == 'v' ? 0 :
                                    returnType == 'B' ? 1 :
                                    sizeof(uint64_t);
    uint64_t encodedReturnType = r_msg2(signature, "methodReturnType",
                                        0, 0, 0, 0);
    if (returnLength != expectedReturnLength ||
        !sbc_remote_type_equals(encodedReturnType, returnType)) {
        return false;
    }
    if (userArgCount != 0) {
        uint64_t sizeStorage = r_dlsym_call(R_TIMEOUT, "malloc",
                                            2 * sizeof(uint64_t),
                                            0, 0, 0, 0, 0, 0, 0);
        if (!sizeStorage) return false;
        bool argumentSizesValid = true;
        for (size_t i = 0; i < userArgCount; i++) {
            uint64_t encodedType = r_msg2(signature,
                                           "getArgumentTypeAtIndex:",
                                           i + 2, 0, 0, 0);
            remote_write64(sizeStorage, 0);
            remote_write64(sizeStorage + sizeof(uint64_t), 0);
            uint64_t nextType = r_dlsym_call(
                R_TIMEOUT, "NSGetSizeAndAlignment",
                encodedType, sizeStorage,
                sizeStorage + sizeof(uint64_t), 0, 0, 0, 0, 0);
            uint64_t actualSize = remote_read64(sizeStorage);
            uint64_t expectedSize = argTypes[i] == 'B' ? 1 :
                                    sizeof(uint64_t);
            if (!encodedType || !nextType || actualSize != expectedSize ||
                !sbc_remote_type_equals(encodedType, argTypes[i]) ||
                !remote_call_current_success()) {
                argumentSizesValid = false;
                break;
            }
        }
        r_free(sizeStorage);
        if (!argumentSizesValid || !remote_call_current_success()) return false;
    }
    if (!remote_call_current_success()) return false;
    sbc_method_shape_cache_store(pid, objectClass, selector,
                                 returnType, argTypes);
    return true;
}

static bool sbc_retain_main(uint64_t obj)
{
    if (!r_is_objc_ptr(obj)) return false;
    return r_msg2_main(obj, "retain", 0, 0, 0, 0) == obj &&
           remote_call_current_success();
}

static void sbc_release_main(uint64_t obj)
{
    if (r_is_objc_ptr(obj)) r_msg2_main(obj, "release", 0, 0, 0, 0);
}

static bool sbc_read_count(uint64_t obj, const char *selectorName,
                           uint64_t *valueOut)
{
    if (valueOut) *valueOut = 0;
    if (!r_is_objc_ptr(obj) || !r_responds_main(obj, selectorName)) return false;
    uint64_t value = r_msg2_main(obj, selectorName, 0, 0, 0, 0);
    if (!remote_call_current_success()) return false;
    if (valueOut) *valueOut = value;
    return true;
}

static bool sbc_read_bool_object_arg(uint64_t obj, const char *selectorName,
                                     uint64_t argument, bool *valueOut)
{
    if (valueOut) *valueOut = false;
    if (!sbc_method_shape(obj, selectorName, 'B', "@")) return false;
    bool value = r_msg2_main(obj, selectorName, argument, 0, 0, 0) != 0;
    if (!remote_call_current_success()) return false;
    if (valueOut) *valueOut = value;
    return true;
}

static bool sbc_object_getter(uint64_t obj, const char *selectorName,
                              uint64_t *valueOut)
{
    if (valueOut) *valueOut = 0;
    if (!r_is_objc_ptr(obj) || !r_responds_main(obj, selectorName)) return false;
    uint64_t value = r_msg2_main(obj, selectorName, 0, 0, 0, 0);
    if (!r_is_objc_ptr(value) || !remote_call_current_success()) return false;
    if (valueOut) *valueOut = value;
    return true;
}

typedef struct {
    uint64_t array;
    uint64_t count;
} SBCIconSnapshot;

static void sbc_release_icon_snapshot(SBCIconSnapshot *snapshot)
{
    if (!snapshot || !r_is_objc_ptr(snapshot->array)) return;
    uint64_t releaseSelector = r_sel("release");
    if (releaseSelector) r_msg(snapshot->array, releaseSelector, 0, 0, 0, 0);
    memset(snapshot, 0, sizeof(*snapshot));
}

static bool sbc_take_icon_snapshot(uint64_t list, SBCIconSnapshot *snapshot)
{
    if (snapshot) memset(snapshot, 0, sizeof(*snapshot));
    if (!snapshot || !r_is_objc_ptr(list) ||
        !r_responds_main(list, "icons")) {
        return false;
    }

    // Cache the scalar NSArray selectors before asking main for the immutable
    // copy. The retained-object bridge closes the +0 return window before its
    // backing NSInvocation is released.
    uint64_t countSelector = r_sel("count");
    uint64_t objectSelector = r_sel("objectAtIndex:");
    if (!countSelector || !objectSelector) return false;

    uint64_t array = r_msg2_main_retained_object(list, "icons", 0, 0, 0, 0);
    if (!r_is_objc_ptr(array) || !remote_call_current_success()) return false;
    if (!r_responds(array, "count") ||
        !r_responds(array, "objectAtIndex:")) {
        SBCIconSnapshot temporary = { .array = array, .count = 0 };
        sbc_release_icon_snapshot(&temporary);
        return false;
    }

    uint64_t count = r_msg(array, countSelector, 0, 0, 0, 0);
    if (!remote_call_current_success() || count > SBC_MAX_ICONS_PER_LIST) {
        SBCIconSnapshot temporary = { .array = array, .count = 0 };
        sbc_release_icon_snapshot(&temporary);
        return false;
    }

    snapshot->array = array;
    snapshot->count = count;
    return true;
}

static bool sbc_icon_snapshot_at(const SBCIconSnapshot *snapshot,
                                 uint64_t index, uint64_t *iconOut)
{
    if (iconOut) *iconOut = 0;
    if (!snapshot || !r_is_objc_ptr(snapshot->array) ||
        index >= snapshot->count) {
        return false;
    }
    uint64_t selector = r_sel("objectAtIndex:");
    if (!selector) return false;
    uint64_t icon = r_msg(snapshot->array, selector, index, 0, 0, 0);
    if (!r_is_objc_ptr(icon) || !remote_call_current_success()) return false;
    if (iconOut) *iconOut = icon;
    return true;
}

static bool sbc_icon_snapshots_equal(const SBCIconSnapshot *a,
                                     const SBCIconSnapshot *b)
{
    if (!a || !b || a->count != b->count) return false;
    for (uint64_t i = 0; i < a->count; i++) {
        uint64_t left = 0;
        uint64_t right = 0;
        if (!sbc_icon_snapshot_at(a, i, &left) ||
            !sbc_icon_snapshot_at(b, i, &right) || left != right) {
            return false;
        }
    }
    return true;
}

static bool sbc_copy_root_pages(uint64_t rootFolder,
                                uint64_t *pages,
                                size_t capacity,
                                size_t *countOut)
{
    if (countOut) *countOut = 0;
    if (!r_is_objc_ptr(rootFolder) || (!pages && capacity != 0) ||
        !r_responds_main(rootFolder, "listAtIndex:")) {
        printf("[SBC:DOCK] direct scan failed stage=root-list-abi\n");
        return false;
    }

    uint64_t count = 0;
    if (!sbc_read_count(rootFolder, "listCount", &count) || count > capacity) {
        printf("[SBC:DOCK] direct scan failed stage=root-list-count count=%llu cap=%zu\n",
               (unsigned long long)count, capacity);
        return false;
    }

    for (uint64_t i = 0; i < count; i++) {
        uint64_t page = r_msg2_main(rootFolder, "listAtIndex:",
                                    i, 0, 0, 0);
        if (!r_is_objc_ptr(page) || !remote_call_current_success()) {
            printf("[SBC:DOCK] direct scan failed stage=root-list-element page=%llu\n",
                   (unsigned long long)i);
            return false;
        }
        for (uint64_t j = 0; j < i; j++) {
            if (pages[j] == page) {
                printf("[SBC:DOCK] direct scan failed stage=duplicate-root-list page=%llu\n",
                       (unsigned long long)i);
                return false;
            }
        }
        uint64_t folder = 0;
        if (!sbc_object_getter(page, "folder", &folder) || folder != rootFolder) {
            printf("[SBC:DOCK] direct scan failed stage=root-list-owner page=%llu\n",
                   (unsigned long long)i);
            return false;
        }
        pages[i] = page;
    }

    if (countOut) *countOut = (size_t)count;
    return true;
}

static bool sbc_root_contains_page(uint64_t rootFolder, uint64_t list)
{
    uint64_t pages[SBC_MAX_ROOT_PAGES] = {0};
    size_t count = 0;
    if (!sbc_copy_root_pages(rootFolder, pages, SBC_MAX_ROOT_PAGES, &count))
        return false;
    for (size_t i = 0; i < count; i++) {
        if (pages[i] == list) return true;
    }
    return false;
}

static int clamp(int v, int lo, int hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static uint64_t try_msg0(uint64_t obj, const char *selName)
{
    if (!r_is_objc_ptr(obj) || !r_responds_main(obj, selName)) return 0;
    return r_msg2_main(obj, selName, 0, 0, 0, 0);
}

static void disable_list_autofit(uint64_t listView, const char *tag)
{
    if (!r_is_objc_ptr(listView) ||
        !r_responds_main(listView, "setAutomaticallyAdjustsLayoutMetricsToFit:")) return;
    r_msg2_main(listView, "setAutomaticallyAdjustsLayoutMetricsToFit:",
                0, 0, 0, 0);
    printf("[SBC] v3: %s autoFit=NO\n", tag);
}

static uint64_t list_view_model(uint64_t listView)
{
    uint64_t model = try_msg0(listView, "model");
    if (!model) model = try_msg0(listView, "iconListModel");
    if (!model) model = try_msg0(listView, "displayedModel");
    return model;
}

static bool patch_list_model_grid(uint64_t listView, const char *tag, int cols, int rows)
{
    if (!r_is_objc_ptr(listView)) return false;

    uint64_t model = list_view_model(listView);
    if (!r_is_objc_ptr(model) || !r_responds_main(model, "gridSize")) {
        printf("[SBC] v3: %s missing grid model\n", tag);
        return false;
    }

    uint64_t newGrid = (((uint64_t)rows & 0xffffULL) << 16) | ((uint64_t)cols & 0xffffULL);
    uint64_t oldGrid = r_msg2_main(model, "gridSize", 0, 0, 0, 0) & 0xffffffffULL;

    if (r_responds_main(model, "setGridSize:")) {
        r_msg2_main(model, "setGridSize:", newGrid, 0, 0, 0);
    } else if (r_responds_main(model, "changeGridSize:options:")) {
        r_msg2_main(model, "changeGridSize:options:", newGrid, 0, 0, 0);
    } else {
        printf("[SBC] v3: %s model lacks grid setter\n", tag);
        return false;
    }

    uint64_t afterGrid = r_msg2_main(model, "gridSize", 0, 0, 0, 0) & 0xffffffffULL;
    printf("[SBC] v3: %s model gridSize 0x%llx -> 0x%llx\n", tag, oldGrid, afterGrid);
    return afterGrid == newGrid;
}

static void patch_dock(uint64_t iconCtrl, int dockIcons)
{
    uint64_t mgr = try_msg0(iconCtrl, "iconManager");
    if (!mgr) { printf("[SBC] dock: nil iconManager\n"); return; }
    usleep(50000);

    uint64_t dock = try_msg0(mgr, "dockListView");
    if (!dock) dock = try_msg0(iconCtrl, "dockListView");
    if (!dock) { printf("[SBC] dock: nil dockListView\n"); return; }
    disable_list_autofit(dock, "dockListView");
    usleep(50000);

    uint64_t model = try_msg0(dock, "model");
    if (!model) model = try_msg0(dock, "iconListModel");
    if (!model) model = try_msg0(dock, "displayedModel");
    if (model && r_responds_main(model, "gridSize") &&
        r_responds_main(model, "setGridSize:")) {
        uint64_t oldGrid = r_msg2_main(model, "gridSize", 0, 0, 0, 0) & 0xffffffffULL;
        uint64_t newGrid = (oldGrid & 0xffff0000ULL) | (uint64_t)dockIcons;
        usleep(50000);
        r_msg2_main(model, "setGridSize:", newGrid, 0, 0, 0);
        printf("[SBC] dock: gridSize 0x%llx -> 0x%llx\n", oldGrid, newGrid);
    }
    usleep(50000);

    uint64_t layout = try_msg0(dock, "layout");
    if (layout) {
        usleep(50000);
        uint64_t cfg = try_msg0(layout, "layoutConfiguration");
        if (cfg && r_responds_main(cfg, "setNumberOfPortraitColumns:")) {
            usleep(50000);
            r_msg2_main(cfg, "setNumberOfPortraitColumns:",
                        (uint64_t)dockIcons, 0, 0, 0);
            printf("[SBC] dock: portraitColumns -> %d\n", dockIcons);
        }
    }
    usleep(50000);

    if (r_responds_main(dock, "setNeedsLayout")) {
        uint64_t selSetNeedsLayout = r_sel("setNeedsLayout");
        r_perform_main(dock, selSetNeedsLayout, 0, false);
    }
}

static int patch_homescreen_list_models_v3(uint64_t mgr, int cols, int rows)
{
    uint64_t rootFolder = try_msg0(mgr, "rootFolderController");
    if (!r_is_objc_ptr(rootFolder)) {
        printf("[SBC] v3: nil rootFolderController\n");
        return 0;
    }

    int touched = 0;
    if (r_responds_main(rootFolder, "iconListViewCount") &&
        r_responds_main(rootFolder, "iconListViewAtIndex:")) {
        uint64_t count = r_msg2_main(rootFolder, "iconListViewCount", 0, 0, 0, 0);
        uint64_t limit = count < 64 ? count : 64;
        printf("[SBC] v3: iconListViewCount=%llu\n", count);
        for (uint64_t i = 0;
             i < limit && remote_call_current_success();
             i++) {
            uint64_t listView = r_msg2_main(rootFolder, "iconListViewAtIndex:",
                                            i, 0, 0, 0);
            if (!r_is_objc_ptr(listView)) continue;

            char tag[32];
            snprintf(tag, sizeof(tag), "page[%llu]", i);
            disable_list_autofit(listView, tag);
            if (patch_list_model_grid(listView, tag, cols, rows)) touched++;
        }
    } else if (r_responds_main(rootFolder, "currentIconListView")) {
        uint64_t current = r_msg2_main(rootFolder, "currentIconListView", 0, 0, 0, 0);
        disable_list_autofit(current, "currentIconListView");
        if (patch_list_model_grid(current, "currentIconListView", cols, rows)) touched++;
    } else {
        printf("[SBC] v3: no list-view accessor path\n");
    }

    uint64_t dockListView = try_msg0(mgr, "dockListView");
    if (r_is_objc_ptr(dockListView)) {
        disable_list_autofit(dockListView, "dockListView");
    }

    printf("[SBC] v3: patched home list models=%d\n", touched);
    return touched;
}

static void patch_homescreen_grid(uint64_t iconCtrl, int cols, int rows, bool hideLabels)
{
    uint64_t mgr = try_msg0(iconCtrl, "iconManager");
    if (!mgr) { printf("[SBC] hs: nil iconManager\n"); return; }
    usleep(50000);

    uint64_t provider = try_msg0(mgr, "listLayoutProvider");
    if (provider) {
        usleep(50000);

        uint64_t loc = r_cfstr("SBIconLocationRoot");
        if (!loc) {
            printf("[SBC] hs: cfstr failed\n");
        } else if (!r_responds_main(provider, "layoutForIconLocation:")) {
            printf("[SBC] hs: provider lacks layoutForIconLocation:\n");
        } else {
            uint64_t layout = r_msg2_main(provider, "layoutForIconLocation:",
                                          loc, 0, 0, 0);
            if (!layout) {
                printf("[SBC] hs: nil layout for root\n");
            } else {
                usleep(50000);
                uint64_t cfg = try_msg0(layout, "layoutConfiguration");
                if (!cfg) {
                    printf("[SBC] hs: nil layoutConfiguration\n");
                } else if (!r_responds_main(cfg, "setNumberOfPortraitColumns:")) {
                    printf("[SBC] hs: cfg lacks setNumberOfPortraitColumns:\n");
                } else {
                    usleep(50000);
                    r_msg2_main(cfg, "setNumberOfPortraitColumns:",
                                (uint64_t)cols, 0, 0, 0);
                    usleep(50000);
                    if (r_responds_main(cfg, "setNumberOfPortraitRows:"))
                        r_msg2_main(cfg, "setNumberOfPortraitRows:",
                                    (uint64_t)rows, 0, 0, 0);
                    usleep(50000);
                    if (r_responds_main(cfg, "setNumberOfLandscapeColumns:"))
                        r_msg2_main(cfg, "setNumberOfLandscapeColumns:",
                                    (uint64_t)rows, 0, 0, 0);
                    usleep(50000);
                    if (r_responds_main(cfg, "setNumberOfLandscapeRows:"))
                        r_msg2_main(cfg, "setNumberOfLandscapeRows:",
                                    (uint64_t)cols, 0, 0, 0);
                    printf("[SBC] hs: provider cols=%d rows=%d\n", cols, rows);

                    if (hideLabels && r_responds_main(cfg, "setShowsLabels:")) {
                        usleep(50000);
                        r_msg2_main(cfg, "setShowsLabels:", 0, 0, 0, 0);
                        printf("[SBC] hs: showsLabels=NO\n");
                    }
                }
            }
        }
        if (loc && remote_call_current_success()) {
            r_dlsym_call(R_TIMEOUT, "CFRelease", loc, 0, 0, 0, 0, 0, 0, 0);
        }
    } else {
        printf("[SBC] hs: nil listLayoutProvider\n");
    }

    patch_homescreen_list_models_v3(mgr, cols, rows);
}

typedef struct {
    uint64_t icon;
    uint64_t sourceList;
    uint64_t sourceIndex;
    char bundleID[192];
    bool retained;
} SBCDockPendingMove;

static void sbc_release_pending_moves(SBCDockPendingMove *moves, size_t count)
{
    if (!moves) return;
    for (size_t i = 0; i < count; i++) {
        if (!moves[i].retained) continue;
        sbc_release_main(moves[i].sourceList);
        sbc_release_main(moves[i].icon);
        moves[i].retained = false;
    }
}

static bool sbc_find_dock_runtime(uint64_t iconCtrl, uint64_t *modelOut,
                                  uint64_t *rootOut, uint64_t *dockOut)
{
    if (modelOut) *modelOut = 0;
    if (rootOut) *rootOut = 0;
    if (dockOut) *dockOut = 0;

    uint64_t manager = 0;
    (void)sbc_object_getter(iconCtrl, "iconManager", &manager);

    uint64_t model = 0;
    if (!sbc_object_getter(manager, "iconModel", &model) &&
        !sbc_object_getter(iconCtrl, "model", &model)) {
        printf("[SBC:DOCK] canonical icon model unavailable\n");
        return false;
    }

    uint64_t root = 0;
    if (!sbc_object_getter(manager, "rootFolder", &root) &&
        !sbc_object_getter(iconCtrl, "rootFolder", &root) &&
        !sbc_object_getter(model, "rootFolder", &root)) {
        printf("[SBC:DOCK] root folder unavailable\n");
        return false;
    }

    uint64_t rootModel = 0;
    if (!sbc_object_getter(root, "model", &rootModel) || rootModel != model) {
        printf("[SBC:DOCK] icon model/root folder identity mismatch\n");
        return false;
    }
    uint64_t modelRoot = 0;
    if (!sbc_object_getter(model, "rootFolder", &modelRoot) || modelRoot != root) {
        printf("[SBC:DOCK] model does not own the active root folder\n");
        return false;
    }

    uint64_t dock = 0;
    if (!sbc_object_getter(root, "dock", &dock)) {
        printf("[SBC:DOCK] SBRootFolder.dock unavailable\n");
        return false;
    }

    uint64_t dockFolder = 0;
    if (!sbc_object_getter(dock, "folder", &dockFolder) || dockFolder != root) {
        printf("[SBC:DOCK] dock model is not attached to the active root folder\n");
        return false;
    }

    if (modelOut) *modelOut = model;
    if (rootOut) *rootOut = root;
    if (dockOut) *dockOut = dock;
    return true;
}

typedef struct {
    uint64_t candidateCount;
    uint64_t dockCount;
    uint64_t rootPageCount;
    uint64_t ambiguousCount;
    uint64_t dockIcon;
    uint64_t dockIconIndex;
    uint64_t rootPageIcon;
    uint64_t rootPageList;
    uint64_t rootPageIconIndex;
    uint64_t pagesScanned;
    uint64_t iconsScanned;
} SBCApplicationPlacements;

typedef struct {
    uint64_t matchCount;
    uint64_t icon;
    uint64_t index;
    uint64_t iconsScanned;
} SBCListBundleScan;

static bool sbc_direct_icon_matches_bundle(uint64_t icon,
                                           uint64_t remoteBundleID,
                                           bool *matchesOut)
{
    if (matchesOut) *matchesOut = false;
    if (!r_is_objc_ptr(icon) || !r_is_objc_ptr(remoteBundleID)) return false;

    // applicationBundleID is the exact getter used internally by
    // lastDirectlyContainedLeafIconWithApplicationBundleIdentifier:. Calling
    // it directly avoids repeating full method-signature/encoding reads for
    // every icon. Non-application icons simply produce no object and are
    // ignored; an invalid object result is treated as an unstable model.
    uint64_t bundleSelector = r_sel("applicationBundleID");
    uint64_t equalSelector = r_sel("isEqualToString:");
    if (!bundleSelector || !equalSelector) return false;
    if (!r_responds_main(icon, "applicationBundleID"))
        return remote_call_current_success();
    uint64_t actualBundleID = r_msg_main(icon, bundleSelector, 0, 0, 0, 0);
    if (!remote_call_current_success()) return false;
    if (!actualBundleID) return true;
    if (!r_is_objc_ptr(actualBundleID)) return false;

    bool matches = r_msg_main(remoteBundleID, equalSelector,
                              actualBundleID, 0, 0, 0) != 0;
    if (!remote_call_current_success()) return false;
    if (matchesOut) *matchesOut = matches;
    return true;
}

static bool sbc_scan_list_for_bundle(uint64_t list,
                                     uint64_t remoteBundleID,
                                     SBCListBundleScan *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (out) out->index = UINT64_MAX;
    if (!out || !r_is_objc_ptr(list) || !r_is_objc_ptr(remoteBundleID) ||
        !r_responds_main(
            list,
            "lastDirectlyContainedLeafIconWithApplicationBundleIdentifier:")) {
        printf("[SBC:DOCK] direct scan failed stage=list-bundle-probe-abi list=0x%llx\n",
               (unsigned long long)list);
        return false;
    }

    uint64_t expectedLast = r_msg2_main(
        list, "lastDirectlyContainedLeafIconWithApplicationBundleIdentifier:",
        remoteBundleID, 0, 0, 0);
    if (!remote_call_current_success()) {
        printf("[SBC:DOCK] direct scan failed stage=list-bundle-probe list=0x%llx\n",
               (unsigned long long)list);
        return false;
    }
    if (!expectedLast) return true;
    if (!r_is_objc_ptr(expectedLast)) {
        printf("[SBC:DOCK] direct scan failed stage=list-bundle-probe-result list=0x%llx\n",
               (unsigned long long)list);
        return false;
    }
    if (!r_responds_main(expectedLast, "isApplicationIcon") ||
        r_msg2_main(expectedLast, "isApplicationIcon", 0, 0, 0, 0) == 0 ||
        !remote_call_current_success()) {
        printf("[SBC:DOCK] direct scan failed stage=non-application-leaf list=0x%llx\n",
               (unsigned long long)list);
        return false;
    }

    if (!r_responds_main(expectedLast, "applicationBundleID") ||
        !r_responds_main(remoteBundleID, "isEqualToString:")) {
        printf("[SBC:DOCK] direct scan failed stage=icon-bundle-abi list=0x%llx\n",
               (unsigned long long)list);
        return false;
    }

    SBCIconSnapshot snapshot = {0};
    SBCIconSnapshot verification = {0};
    bool result = false;
    uint64_t matchCount = 0;
    uint64_t expectedOccurrences = 0;
    uint64_t expectedIndex = UINT64_MAX;
    uint64_t lastMatch = 0;
    uint64_t lastMatchIndex = UINT64_MAX;

    if (!sbc_take_icon_snapshot(list, &snapshot) || snapshot.count == 0) {
        printf("[SBC:DOCK] direct scan failed stage=list-snapshot list=0x%llx\n",
               (unsigned long long)list);
        goto cleanup;
    }

    for (uint64_t i = 0; i < snapshot.count; i++) {
        uint64_t icon = 0;
        if (!sbc_icon_snapshot_at(&snapshot, i, &icon)) {
            printf("[SBC:DOCK] direct scan failed stage=snapshot-element list=0x%llx index=%llu\n",
                   (unsigned long long)list, (unsigned long long)i);
            goto cleanup;
        }
        out->iconsScanned++;
        if (icon == expectedLast) {
            expectedOccurrences++;
            if (expectedIndex == UINT64_MAX) expectedIndex = i;
        }

        bool matches = false;
        if (!sbc_direct_icon_matches_bundle(icon, remoteBundleID, &matches)) {
            printf("[SBC:DOCK] direct scan failed stage=icon-bundle-read list=0x%llx index=%llu\n",
                   (unsigned long long)list, (unsigned long long)i);
            goto cleanup;
        }
        if (!matches) continue;
        matchCount++;
        lastMatch = icon;
        lastMatchIndex = i;
    }

    if (matchCount > 1 || expectedOccurrences > 1) {
        out->matchCount = matchCount > 1 ? matchCount : 2;
        out->icon = expectedLast;
        out->index = expectedIndex;
        printf("[SBC:DOCK] direct scan ambiguous stage=snapshot-duplicate list=0x%llx matches=%llu pointerOccurrences=%llu\n",
               (unsigned long long)list,
               (unsigned long long)matchCount,
               (unsigned long long)expectedOccurrences);
        result = true;
        goto cleanup;
    }
    if (matchCount != 1 || expectedOccurrences != 1 ||
        lastMatch != expectedLast || lastMatchIndex != expectedIndex) {
        printf("[SBC:DOCK] direct scan failed stage=snapshot-probe-validation list=0x%llx matches=%llu occurrences=%llu\n",
               (unsigned long long)list,
               (unsigned long long)matchCount,
               (unsigned long long)expectedOccurrences);
        goto cleanup;
    }

    // Take a second immutable model snapshot after the scan. Exact pointer
    // order equality closes the same-count replacement/reorder race without
    // indexing the live mutable list between remote calls.
    if (!sbc_take_icon_snapshot(list, &verification) ||
        !sbc_icon_snapshots_equal(&snapshot, &verification)) {
        printf("[SBC:DOCK] direct scan failed stage=list-changed list=0x%llx\n",
               (unsigned long long)list);
        goto cleanup;
    }
    uint64_t finalLast = r_msg2_main(
        list, "lastDirectlyContainedLeafIconWithApplicationBundleIdentifier:",
        remoteBundleID, 0, 0, 0);
    if (!remote_call_current_success() || finalLast != expectedLast) {
        printf("[SBC:DOCK] direct scan failed stage=list-bundle-changed list=0x%llx\n",
               (unsigned long long)list);
        goto cleanup;
    }

    out->matchCount = 1;
    out->icon = expectedLast;
    out->index = expectedIndex;
    result = true;

cleanup:
    sbc_release_icon_snapshot(&verification);
    sbc_release_icon_snapshot(&snapshot);
    return result && remote_call_current_success();
}

static bool sbc_resolve_application_placements(uint64_t root,
                                               uint64_t dock,
                                               const char *bundleID,
                                               SBCApplicationPlacements *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !bundleID || !bundleID[0]) return false;

    uint64_t remoteBundleID = r_nsstr_retained(bundleID);
    if (!r_is_objc_ptr(remoteBundleID)) {
        printf("[SBC:DOCK] direct scan failed stage=bundle-allocation bundle=%s\n",
               bundleID);
        return false;
    }

    bool ok = true;
    SBCListBundleScan listScan = {0};
    if (!sbc_scan_list_for_bundle(dock, remoteBundleID, &listScan)) {
        ok = false;
    } else {
        out->candidateCount += listScan.matchCount;
        out->dockCount += listScan.matchCount;
        out->iconsScanned += listScan.iconsScanned;
        if (listScan.matchCount > 1)
            out->ambiguousCount += listScan.matchCount - 1;
        if (listScan.matchCount != 0) {
            out->dockIcon = listScan.icon;
            out->dockIconIndex = listScan.index;
        }
    }

    uint64_t pages[SBC_MAX_ROOT_PAGES] = {0};
    size_t pageCount = 0;
    if (ok && !sbc_copy_root_pages(root, pages, SBC_MAX_ROOT_PAGES,
                                   &pageCount)) {
        ok = false;
    }
    for (size_t i = 0; ok && i < pageCount; i++) {
        memset(&listScan, 0, sizeof(listScan));
        if (!sbc_scan_list_for_bundle(pages[i], remoteBundleID, &listScan)) {
            ok = false;
            break;
        }
        out->pagesScanned++;
        out->iconsScanned += listScan.iconsScanned;
        out->candidateCount += listScan.matchCount;
        out->rootPageCount += listScan.matchCount;
        if (listScan.matchCount > 1)
            out->ambiguousCount += listScan.matchCount - 1;
        if (listScan.matchCount != 0) {
            out->rootPageIcon = listScan.icon;
            out->rootPageList = pages[i];
            out->rootPageIconIndex = listScan.index;
        }
        if (out->candidateCount > 1) break;
    }
    sbc_release_main(remoteBundleID);
    return ok && remote_call_current_success();
}

static void sbc_log_application_placements(const char *bundleID,
                                           const SBCApplicationPlacements *p)
{
    if (!bundleID || !p) return;
    printf("[SBC:DOCK] direct scan %s candidates=%llu dock=%llu pages=%llu ambiguous=%llu pagesScanned=%llu iconsScanned=%llu\n",
           bundleID,
           (unsigned long long)p->candidateCount,
           (unsigned long long)p->dockCount,
           (unsigned long long)p->rootPageCount,
           (unsigned long long)p->ambiguousCount,
           (unsigned long long)p->pagesScanned,
           (unsigned long long)p->iconsScanned);
}

static void sbc_release_empty_state_containers(void);

static bool sbc_begin_dock_state(uint64_t model, uint64_t root, uint64_t dock)
{
    if (sbcustomizer_has_remote_state()) return false;
    if (!sbc_retain_main(model)) return false;
    if (!sbc_retain_main(root)) {
        sbc_release_main(model);
        return false;
    }
    if (!sbc_retain_main(dock)) {
        sbc_release_main(root);
        sbc_release_main(model);
        return false;
    }

    memset(&gSBCDockState, 0, sizeof(gSBCDockState));
    gSBCDockState.pid = remote_call_current_pid();
    gSBCDockState.iconModel = model;
    gSBCDockState.rootFolder = root;
    gSBCDockState.dockList = dock;

    // Hold a short-lived autosave guard only while the model is mutated.  The
    // guard is released before the explicit save below; it is never retained
    // as a session/rollback token after this one-shot operation returns.
    uint64_t assertion = 0;
    bool assertionRetained = false;
    bool assertionInvalidatable = false;
    if (sbc_method_shape(model, "disableIconStateAutosaveForReason:", '@', "@")) {
        uint64_t reason = r_nsstr_retained("kslop SBC dock commit");
        assertion = r_is_objc_ptr(reason)
            ? r_msg2_main(model, "disableIconStateAutosaveForReason:",
                          reason, 0, 0, 0)
            : 0;
        if (r_is_objc_ptr(assertion)) {
            // The assertion may be autoreleased on SpringBoard's main thread.
            // Retain it before issuing any other main-thread invocation.
            assertionRetained = sbc_retain_main(assertion);
        }
        sbc_release_main(reason);
        if (assertionRetained) {
            assertionInvalidatable =
                sbc_method_shape(assertion, "invalidate", 'v', "");
        }
    }
    if (assertionRetained && assertionInvalidatable &&
        remote_call_current_success()) {
        gSBCDockState.autosaveAssertion = assertion;
        printf("[SBC:DOCK] icon-state autosave disabled for dock transaction\n");
        return true;
    }

    if (r_is_objc_ptr(assertion) && assertionInvalidatable)
        r_msg2_main(assertion, "invalidate", 0, 0, 0, 0);
    if (assertionRetained) sbc_release_main(assertion);
    printf("[SBC:DOCK] refused: no safe icon-state autosave assertion\n");
    gSBCDockState.autosaveAssertion = 0;
    sbc_release_empty_state_containers();
    return false;
}

static bool sbc_release_autosave_assertion(void)
{
    uint64_t assertion = gSBCDockState.autosaveAssertion;
    if (!assertion) return true;
    bool ok = true;
    if (sbc_method_shape(assertion, "invalidate", 'v', "")) {
        r_msg2_main(assertion, "invalidate", 0, 0, 0, 0);
        ok = remote_call_current_success();
    } else {
        // The assertion is a best-effort safety guard.  Even when a target
        // build does not expose the expected invalidation ABI, release our
        // local ownership and let SpringBoard reclaim it with its model.
        ok = false;
    }
    sbc_release_main(assertion);
    gSBCDockState.autosaveAssertion = 0;
    return ok && remote_call_current_success();
}

static void sbc_release_empty_state_containers(void)
{
    if (gSBCDockState.moveCount || gSBCDockState.autosaveAssertion) return;
    sbc_release_main(gSBCDockState.dockList);
    sbc_release_main(gSBCDockState.rootFolder);
    sbc_release_main(gSBCDockState.iconModel);
    memset(&gSBCDockState, 0, sizeof(gSBCDockState));
}

// The dock move is intentionally a one-shot durable edit.  The model's
// autosave assertion is invalidated before this explicit save; never leave
// persistence to the timer after the RemoteCall channel is closed.
// saveIconStateIfNeeded changed from void to BOOL across SpringBoard releases,
// and BOOL NO means that no save was needed on the BOOL ABI (for example, the
// model was already clean), not that the remote invocation failed.  Transport
// health is therefore the authoritative result for both ABI shapes.
static bool sbc_commit_icon_state(void)
{
    uint64_t model = gSBCDockState.iconModel;
    if (!r_is_objc_ptr(model)) return false;

    bool committed = false;
    if (sbc_method_shape(model, "saveIconStateIfNeeded", 'B', "")) {
        uint64_t saved = r_msg2_main(model, "saveIconStateIfNeeded",
                                     0, 0, 0, 0);
        committed = remote_call_current_success();
        printf("[SBC:DOCK] saveIconStateIfNeeded returned %d (%s)\n",
               saved != 0 ? 1 : 0,
               committed ? (saved != 0 ? "saved" : "already clean/no save needed")
                         : "remote invocation failed");
    } else if (sbc_method_shape(model, "saveIconStateIfNeeded", 'v', "")) {
        r_msg2_main(model, "saveIconStateIfNeeded", 0, 0, 0, 0);
        committed = remote_call_current_success();
        printf("[SBC:DOCK] saveIconStateIfNeeded completed (void ABI)\n");
    } else {
        printf("[SBC:DOCK] refused: icon model lacks saveIconStateIfNeeded\n");
    }
    return committed && remote_call_current_success();
}

typedef enum {
    SBCDockRestoreFailed = 0,
    SBCDockRestoreOwned,
    SBCDockRestoreRelinquished,
} SBCDockRestoreResult;

static bool sbc_find_exact_icon_in_list(uint64_t list, uint64_t target,
                                        uint64_t *occurrencesOut,
                                        uint64_t *indexOut)
{
    if (occurrencesOut) *occurrencesOut = 0;
    if (indexOut) *indexOut = UINT64_MAX;
    if (!r_is_objc_ptr(list) || !r_is_objc_ptr(target)) return false;

    SBCIconSnapshot snapshot = {0};
    if (!sbc_take_icon_snapshot(list, &snapshot)) return false;

    uint64_t occurrences = 0;
    uint64_t foundIndex = UINT64_MAX;
    bool ok = true;
    for (uint64_t i = 0; i < snapshot.count; i++) {
        uint64_t icon = 0;
        if (!sbc_icon_snapshot_at(&snapshot, i, &icon)) {
            ok = false;
            break;
        }
        if (icon != target) continue;
        occurrences++;
        if (foundIndex == UINT64_MAX) foundIndex = i;
    }
    sbc_release_icon_snapshot(&snapshot);
    if (!ok || !remote_call_current_success()) return false;

    if (occurrencesOut) *occurrencesOut = occurrences;
    if (indexOut) *indexOut = foundIndex;
    return true;
}

static bool sbc_dock_matches_original_state(void)
{
    if (gSBCDockState.originalDockCount > SBC_MAX_DOCK_MOVES) return false;
    SBCIconSnapshot snapshot = {0};
    if (!sbc_take_icon_snapshot(gSBCDockState.dockList, &snapshot) ||
        snapshot.count != gSBCDockState.originalDockCount) {
        sbc_release_icon_snapshot(&snapshot);
        return false;
    }
    bool matches = true;
    for (size_t i = 0; i < gSBCDockState.originalDockCount; i++) {
        uint64_t icon = 0;
        if (!sbc_icon_snapshot_at(&snapshot, i, &icon) ||
            icon != gSBCDockState.originalDockIcons[i]) {
            matches = false;
            break;
        }
    }
    sbc_release_icon_snapshot(&snapshot);
    return matches && remote_call_current_success();
}

static bool sbc_restore_original_dock_order(void)
{
    if (sbc_dock_matches_original_state()) return true;
    if (gSBCDockState.originalDockCount > SBC_MAX_DOCK_MOVES ||
        !sbc_method_shape(gSBCDockState.dockList,
                          "insertIcon:atIndex:", '@', "@Q")) {
        return false;
    }

    uint64_t count = 0;
    if (!sbc_read_count(gSBCDockState.dockList, "numberOfIcons", &count) ||
        count != gSBCDockState.originalDockCount) {
        return false;
    }
    for (size_t i = 0; i < gSBCDockState.originalDockCount; i++) {
        for (size_t j = 0; j < i; j++) {
            if (gSBCDockState.originalDockIcons[i] ==
                gSBCDockState.originalDockIcons[j]) {
                return false;
            }
        }
        uint64_t occurrences = 0;
        if (!sbc_find_exact_icon_in_list(gSBCDockState.dockList,
                                         gSBCDockState.originalDockIcons[i],
                                         &occurrences, NULL) ||
            occurrences != 1) {
            return false;
        }
    }

    // Membership is identical and every pointer is unique, so each insertion
    // is a within-dock reorder rather than an add/remove from another list.
    for (size_t i = 0; i < gSBCDockState.originalDockCount; i++) {
        uint64_t current = 0;
        if (!sbc_icon_at_index(gSBCDockState.dockList, i, &current))
            return false;
        if (current == gSBCDockState.originalDockIcons[i]) continue;
        (void)r_msg2_main(gSBCDockState.dockList, "insertIcon:atIndex:",
                          gSBCDockState.originalDockIcons[i], i, 0, 0);
        if (!remote_call_current_success()) return false;
    }
    return sbc_dock_matches_original_state();
}

static bool sbc_find_exact_icon_in_root_pages(uint64_t root,
                                              uint64_t target,
                                              uint64_t sourceList,
                                              uint64_t *totalOccurrencesOut,
                                              uint64_t *sourceOccurrencesOut,
                                              uint64_t *sourceIndexOut)
{
    if (totalOccurrencesOut) *totalOccurrencesOut = 0;
    if (sourceOccurrencesOut) *sourceOccurrencesOut = 0;
    if (sourceIndexOut) *sourceIndexOut = UINT64_MAX;

    uint64_t pages[SBC_MAX_ROOT_PAGES] = {0};
    size_t pageCount = 0;
    if (!sbc_copy_root_pages(root, pages, SBC_MAX_ROOT_PAGES, &pageCount))
        return false;

    uint64_t totalOccurrences = 0;
    uint64_t sourceOccurrences = 0;
    uint64_t sourceIndex = UINT64_MAX;
    for (size_t i = 0; i < pageCount; i++) {
        uint64_t occurrences = 0;
        uint64_t index = UINT64_MAX;
        if (!sbc_find_exact_icon_in_list(pages[i], target,
                                         &occurrences, &index)) {
            return false;
        }
        totalOccurrences += occurrences;
        if (pages[i] == sourceList) {
            sourceOccurrences = occurrences;
            sourceIndex = index;
        }
    }

    if (totalOccurrencesOut) *totalOccurrencesOut = totalOccurrences;
    if (sourceOccurrencesOut) *sourceOccurrencesOut = sourceOccurrences;
    if (sourceIndexOut) *sourceIndexOut = sourceIndex;
    return true;
}

static bool sbc_move_exactly_at_original_source(SBCDockMove *move)
{
    if (!move || !move->active) return false;
    uint64_t rootOccurrences = 0;
    uint64_t sourceOccurrences = 0;
    uint64_t sourceIndex = UINT64_MAX;
    uint64_t dockOccurrences = 0;
    return sbc_find_exact_icon_in_root_pages(gSBCDockState.rootFolder,
                                             move->icon, move->sourceList,
                                             &rootOccurrences,
                                             &sourceOccurrences,
                                             &sourceIndex) &&
           sbc_find_exact_icon_in_list(gSBCDockState.dockList, move->icon,
                                       &dockOccurrences, NULL) &&
           rootOccurrences == 1 && sourceOccurrences == 1 &&
           dockOccurrences == 0 &&
           sourceIndex == move->sourceIndex &&
           remote_call_current_success();
}

// Recovery used only while unwinding an apply that failed in this same
// transaction. It deliberately keys on the retained object pointer, not on a
// bundle lookup that may itself be ambiguous after a partial insertion.
static SBCDockRestoreResult sbc_restore_exact_pointer_after_failed_apply(
    SBCDockMove *move)
{
    if (!move || !move->active) return SBCDockRestoreFailed;

    uint64_t sourceFolder = 0;
    uint64_t sourceCount = 0;
    uint64_t sourceMax = 0;
    uint64_t rootOccurrences = 0;
    uint64_t sourceOccurrences = 0;
    uint64_t sourceIndex = UINT64_MAX;
    uint64_t dockOccurrences = 0;
    if (!sbc_object_getter(move->sourceList, "folder", &sourceFolder) ||
        sourceFolder != gSBCDockState.rootFolder ||
        !sbc_root_contains_page(gSBCDockState.rootFolder, move->sourceList) ||
        !sbc_method_shape(move->sourceList, "insertIcon:atIndex:", '@', "@Q") ||
        !sbc_read_count(move->sourceList, "numberOfIcons", &sourceCount) ||
        !sbc_read_count(move->sourceList, "maxNumberOfIcons", &sourceMax) ||
        !sbc_find_exact_icon_in_root_pages(gSBCDockState.rootFolder,
                                           move->icon, move->sourceList,
                                           &rootOccurrences,
                                           &sourceOccurrences,
                                           &sourceIndex) ||
        !sbc_find_exact_icon_in_list(gSBCDockState.dockList, move->icon,
                                     &dockOccurrences, NULL)) {
        return SBCDockRestoreFailed;
    }

    if (rootOccurrences > 1 || sourceOccurrences > 1 ||
        rootOccurrences != sourceOccurrences ||
        dockOccurrences > 1 || rootOccurrences + dockOccurrences > 1) {
        printf("[SBC:DOCK] exact rollback refused: retained icon pointer is duplicated\n");
        return SBCDockRestoreFailed;
    }
    if (sourceOccurrences == 1 && sourceIndex == move->sourceIndex &&
        dockOccurrences == 0) {
        return SBCDockRestoreOwned;
    }

    bool allows = sourceOccurrences == 1;
    if (sourceOccurrences == 0 &&
        (!sbc_read_bool_object_arg(move->sourceList, "allowsAddingIcon:",
                                   move->icon, &allows) ||
         !allows || sourceCount >= sourceMax)) {
        printf("[SBC:DOCK] exact rollback refused: original page has no safe slot\n");
        return SBCDockRestoreFailed;
    }
    if (move->sourceIndex > sourceCount) {
        printf("[SBC:DOCK] exact rollback refused: original index is out of range\n");
        return SBCDockRestoreFailed;
    }

    (void)r_msg2_main(move->sourceList, "insertIcon:atIndex:",
                      move->icon, move->sourceIndex, 0, 0);
    if (!remote_call_current_success() ||
        !sbc_move_exactly_at_original_source(move)) {
        printf("[SBC:DOCK] exact rollback verification failed for %s\n",
               move->bundleID);
        return SBCDockRestoreFailed;
    }
    printf("[SBC:DOCK] exact rollback restored %s\n", move->bundleID);
    return SBCDockRestoreOwned;
}

static bool sbc_current_runtime_matches_state(void)
{
    uint64_t controllerClass = r_class("SBIconController");
    if (!r_is_objc_ptr(controllerClass) ||
        !r_responds_main(controllerClass, "sharedInstance")) return false;
    uint64_t controller = r_msg2_main(controllerClass, "sharedInstance",
                                      0, 0, 0, 0);
    uint64_t model = 0;
    uint64_t root = 0;
    uint64_t dock = 0;
    return r_is_objc_ptr(controller) &&
           sbc_find_dock_runtime(controller, &model, &root, &dock) &&
           model == gSBCDockState.iconModel &&
           root == gSBCDockState.rootFolder &&
           dock == gSBCDockState.dockList;
}

static SBCDockRestoreResult sbc_restore_one_move(SBCDockMove *move,
                                                 bool failedApplyRollback)
{
    if (!move || !move->active) return SBCDockRestoreRelinquished;
    if (failedApplyRollback)
        return sbc_restore_exact_pointer_after_failed_apply(move);

    SBCApplicationPlacements placements = {0};
    if (!sbc_resolve_application_placements(gSBCDockState.rootFolder,
                                            gSBCDockState.dockList,
                                            move->bundleID,
                                            &placements)) {
        return SBCDockRestoreFailed;
    }
    sbc_log_application_placements(move->bundleID, &placements);

    uint64_t placedCount = placements.dockCount + placements.rootPageCount;
    if (placements.ambiguousCount != 0 || placedCount > 1) {
        printf("[SBC:DOCK] restore refused: %s placement became ambiguous\n",
               move->bundleID);
        return SBCDockRestoreFailed;
    }
    if (placedCount == 0) {
        printf("[SBC:DOCK] restore skipped: %s no longer has a direct placed icon\n",
               move->bundleID);
        return SBCDockRestoreRelinquished;
    }

    uint64_t currentIcon = placements.dockCount == 1
        ? placements.dockIcon : placements.rootPageIcon;
    uint64_t containingList = placements.dockCount == 1
        ? gSBCDockState.dockList : placements.rootPageList;
    uint64_t containingIndex = placements.dockCount == 1
        ? placements.dockIconIndex : placements.rootPageIconIndex;
    if (currentIcon != move->icon) {
        if (!sbc_retain_main(currentIcon)) return SBCDockRestoreFailed;
        sbc_release_main(move->icon);
        move->icon = currentIcon;
        printf("[SBC:DOCK] restore re-resolved updated icon for %s\n",
               move->bundleID);
    }

    if (containingList == move->sourceList) {
        if (containingIndex == move->sourceIndex)
            return SBCDockRestoreOwned;

        // A replacement icon was already placed/reordered on its page after
        // apply. Nothing remains in the dock for this transaction to undo, so
        // preserve that newer layout instead of forcing the stale index.
        printf("[SBC:DOCK] restore skipped: %s was repositioned on its page\n",
               move->bundleID);
        return SBCDockRestoreRelinquished;
    }
    if (containingList != gSBCDockState.dockList) {
        // The user moved the icon after apply.  Relinquish ownership rather
        // than overwrite that newer manual choice during cleanup.
        printf("[SBC:DOCK] restore skipped: icon was manually moved elsewhere\n");
        return SBCDockRestoreRelinquished;
    }

    uint64_t sourceFolder = 0;
    if (!sbc_object_getter(move->sourceList, "folder", &sourceFolder) ||
        sourceFolder != gSBCDockState.rootFolder ||
        !sbc_root_contains_page(gSBCDockState.rootFolder, move->sourceList) ||
        !sbc_method_shape(move->sourceList, "insertIcon:atIndex:", '@', "@Q")) {
        printf("[SBC:DOCK] restore refused: original page is no longer valid\n");
        return SBCDockRestoreFailed;
    }

    uint64_t sourceCount = 0;
    uint64_t sourceMax = 0;
    uint64_t dockCount = 0;
    bool allows = false;
    if (!sbc_read_count(move->sourceList, "numberOfIcons", &sourceCount) ||
        !sbc_read_count(move->sourceList, "maxNumberOfIcons", &sourceMax) ||
        !sbc_read_count(gSBCDockState.dockList, "numberOfIcons", &dockCount) ||
        !sbc_read_bool_object_arg(move->sourceList, "allowsAddingIcon:",
                                  move->icon, &allows) ||
        !allows || sourceCount >= sourceMax || move->sourceIndex > sourceCount) {
        printf("[SBC:DOCK] restore refused: original page has no safe slot\n");
        return SBCDockRestoreFailed;
    }

    (void)r_msg2_main(move->sourceList, "insertIcon:atIndex:",
                      move->icon, move->sourceIndex, 0, 0);
    if (!remote_call_current_success()) return SBCDockRestoreFailed;

    uint64_t newSourceCount = 0;
    uint64_t newDockCount = 0;
    SBCApplicationPlacements verification = {0};
    if (!sbc_read_count(move->sourceList, "numberOfIcons", &newSourceCount) ||
        !sbc_read_count(gSBCDockState.dockList, "numberOfIcons", &newDockCount) ||
        !sbc_resolve_application_placements(gSBCDockState.rootFolder,
                                            gSBCDockState.dockList,
                                            move->bundleID,
                                            &verification)) {
        return SBCDockRestoreFailed;
    }
    bool restored = verification.ambiguousCount == 0 &&
                    verification.candidateCount == 1 &&
                    verification.dockCount == 0 &&
                    verification.rootPageCount == 1 &&
                    verification.rootPageIcon == move->icon &&
                    verification.rootPageList == move->sourceList &&
                    verification.rootPageIconIndex == move->sourceIndex &&
                    newSourceCount == sourceCount + 1 &&
                    dockCount > 0 && newDockCount + 1 == dockCount;
    if (!restored) printf("[SBC:DOCK] restore verification failed\n");
    return restored && remote_call_current_success()
        ? SBCDockRestoreOwned : SBCDockRestoreFailed;
}

static bool sbc_move_is_at_original_source(SBCDockMove *move)
{
    if (!move || !move->active) return false;
    SBCApplicationPlacements placements = {0};
    if (!sbc_resolve_application_placements(gSBCDockState.rootFolder,
                                            gSBCDockState.dockList,
                                            move->bundleID,
                                            &placements)) {
        return false;
    }
    return placements.ambiguousCount == 0 &&
           placements.candidateCount == 1 &&
           placements.dockCount == 0 &&
           placements.rootPageCount == 1 &&
           placements.rootPageIcon == move->icon &&
           placements.rootPageList == move->sourceList &&
           placements.rootPageIconIndex == move->sourceIndex &&
           remote_call_current_success();
}

static bool sbc_restore_dock_state_internal(bool failedApplyRollback)
{
    if (!sbcustomizer_has_remote_state()) return true;
    if (failedApplyRollback) gSBCDockState.exactRollbackRequired = true;
    bool exactRollback = failedApplyRollback ||
                         gSBCDockState.exactRollbackRequired;
    if (gSBCDockState.pid <= 0 ||
        gSBCDockState.pid != remote_call_current_pid()) {
        printf("[SBC:DOCK] cannot restore stale RemoteCall pointers\n");
        return false;
    }
    if (!sbc_current_runtime_matches_state()) {
        printf("[SBC:DOCK] cannot restore a detached/rebuilt icon model\n");
        return false;
    }

    bool allRestored = true;
    bool processed[SBC_MAX_DOCK_MOVES] = {0};
    SBCDockRestoreResult results[SBC_MAX_DOCK_MOVES] = {0};

    // Original indexes were captured before any removals.  Restore the lowest
    // index first for each page so later insertions land at their original
    // positions rather than being shifted by a subsequently restored icon.
    for (size_t pass = 0; pass < gSBCDockState.moveCount; pass++) {
        size_t chosen = SBC_MAX_DOCK_MOVES;
        uint64_t lowestIndex = UINT64_MAX;
        for (size_t i = 0; i < gSBCDockState.moveCount; i++) {
            SBCDockMove *candidate = &gSBCDockState.moves[i];
            if (processed[i] || !candidate->active) continue;
            if (chosen == SBC_MAX_DOCK_MOVES ||
                candidate->sourceIndex < lowestIndex) {
                chosen = i;
                lowestIndex = candidate->sourceIndex;
            }
        }
        if (chosen == SBC_MAX_DOCK_MOVES) break;
        processed[chosen] = true;
        results[chosen] = sbc_restore_one_move(&gSBCDockState.moves[chosen],
                                               exactRollback);
    }

    // Verify only after every insertion, because restoring a lower-index icon
    // can shift another icon that looked correct earlier in the transaction.
    for (size_t i = 0; i < gSBCDockState.moveCount; i++) {
        SBCDockMove *move = &gSBCDockState.moves[i];
        if (!move->active) continue;
        bool owned = results[i] == SBCDockRestoreOwned &&
                     (exactRollback
                          ? sbc_move_exactly_at_original_source(move)
                          : sbc_move_is_at_original_source(move));
        bool complete = results[i] == SBCDockRestoreRelinquished || owned;
        if (!complete) {
            allRestored = false;
            continue;
        }
        sbc_release_main(move->sourceList);
        sbc_release_main(move->icon);
        memset(move, 0, sizeof(*move));
    }

    size_t writeIndex = 0;
    for (size_t i = 0; i < gSBCDockState.moveCount; i++) {
        if (!gSBCDockState.moves[i].active) continue;
        if (writeIndex != i) gSBCDockState.moves[writeIndex] = gSBCDockState.moves[i];
        writeIndex++;
    }
    for (size_t i = writeIndex; i < gSBCDockState.moveCount; i++)
        memset(&gSBCDockState.moves[i], 0, sizeof(gSBCDockState.moves[i]));
    gSBCDockState.moveCount = writeIndex;

    if (exactRollback && gSBCDockState.moveCount == 0 &&
        !sbc_restore_original_dock_order()) {
        printf("[SBC:DOCK] exact rollback retained: original dock order was not restored\n");
        allRestored = false;
    }
    if (gSBCDockState.moveCount == 0 &&
        (!exactRollback || allRestored) &&
        !sbc_release_autosave_assertion()) {
        allRestored = false;
    }
    if (gSBCDockState.moveCount == 0 && !gSBCDockState.autosaveAssertion)
        sbc_release_empty_state_containers();
    return allRestored && !sbcustomizer_has_remote_state() &&
           remote_call_current_success();
}

bool sbcustomizer_has_remote_state(void)
{
    return gSBCDockState.moveCount != 0 ||
           gSBCDockState.autosaveAssertion != 0;
}

void sbcustomizer_forget_session_state(void)
{
    memset(&gSBCDockState, 0, sizeof(gSBCDockState));
}

// Release the transient bridge state after a durable save, or after an
// interrupted apply.  A failed apply is deliberately not rolled back: once a
// model mutation has happened, exact reversal is less safe than leaving the
// user's resulting layout alone and dropping every retained remote object.
static bool sbc_discard_dock_state(const char *reason)
{
    if (!sbcustomizer_has_remote_state()) return true;
    printf("[SBC:DOCK] releasing transient dock state%s%s\n",
           reason ? ": " : "", reason ?: "");

    // Never send a message through pointers captured from another SpringBoard
    // instance, or after the transport has been poisoned.  The remote target
    // is then stale/unreachable; clear local bookkeeping and let that process
    // die or reclaim its own objects rather than attempting unsafe IPC.
    if (gSBCDockState.pid <= 0 ||
        gSBCDockState.pid != remote_call_current_pid() ||
        !remote_call_current_success()) {
        memset(&gSBCDockState, 0, sizeof(gSBCDockState));
        return false;
    }

    bool released = sbc_release_autosave_assertion();
    for (size_t i = 0; i < gSBCDockState.moveCount; i++) {
        if (!gSBCDockState.moves[i].active) continue;
        sbc_release_main(gSBCDockState.moves[i].sourceList);
        sbc_release_main(gSBCDockState.moves[i].icon);
        memset(&gSBCDockState.moves[i], 0, sizeof(gSBCDockState.moves[i]));
    }
    gSBCDockState.moveCount = 0;
    sbc_release_main(gSBCDockState.dockList);
    sbc_release_main(gSBCDockState.rootFolder);
    sbc_release_main(gSBCDockState.iconModel);
    memset(&gSBCDockState, 0, sizeof(gSBCDockState));
    return released && remote_call_current_success() &&
           !sbcustomizer_has_remote_state();
}

bool sbcustomizer_stop_in_session(void)
{
    uint32_t previousSettleUS = r_settle_us(0);
    bool released = sbc_discard_dock_state("cleanup");
    r_settle_us(previousSettleUS);
    return released && !sbcustomizer_has_remote_state();
}

static bool sbc_icon_at_index(uint64_t list, uint64_t index, uint64_t *iconOut)
{
    if (iconOut) *iconOut = 0;
    SBCIconSnapshot snapshot = {0};
    if (!sbc_take_icon_snapshot(list, &snapshot)) return false;
    uint64_t icon = 0;
    bool ok = sbc_icon_snapshot_at(&snapshot, index, &icon);
    sbc_release_icon_snapshot(&snapshot);
    if (!ok || !remote_call_current_success()) return false;
    if (iconOut) *iconOut = icon;
    return true;
}

static bool sbc_verify_dock_order(uint64_t dock,
                                  const uint64_t *originalIcons,
                                  size_t originalCount,
                                  const SBCDockPendingMove *moved,
                                  size_t movedCount)
{
    SBCIconSnapshot snapshot = {0};
    if (!sbc_take_icon_snapshot(dock, &snapshot) ||
        snapshot.count != originalCount + movedCount) {
        sbc_release_icon_snapshot(&snapshot);
        return false;
    }

    bool valid = true;
    for (size_t i = 0; i < originalCount; i++) {
        uint64_t icon = 0;
        if (!sbc_icon_snapshot_at(&snapshot, i, &icon) ||
            icon != originalIcons[i]) {
            valid = false;
            break;
        }
    }
    for (size_t i = 0; valid && i < movedCount; i++) {
        uint64_t icon = 0;
        if (!sbc_icon_snapshot_at(&snapshot, originalCount + i, &icon) ||
            icon != moved[i].icon) {
            valid = false;
        }
    }
    sbc_release_icon_snapshot(&snapshot);
    return valid && remote_call_current_success();
}

static bool sbc_apply_ordered_dock_apps(uint64_t iconCtrl, int dockIcons,
                                        NSArray<NSString *> *orderedBundleIDs)
{
    if (dockIcons < 5 || orderedBundleIDs.count == 0) return true;
    if (orderedBundleIDs.count > SBC_MAX_DOCK_MOVES) {
        printf("[SBC:DOCK] refused: selection exceeds dock hard limit\n");
        return false;
    }

    SBCDockPendingMove pending[SBC_MAX_DOCK_MOVES] = {0};
    uint64_t originalDockIcons[SBC_MAX_DOCK_MOVES] = {0};
    size_t pendingCount = 0;
    size_t originalDockCount = 0;
    bool stateStarted = false;
    bool applied = false;

    do {
        uint64_t model = 0;
        uint64_t root = 0;
        uint64_t dock = 0;
        if (!sbc_find_dock_runtime(iconCtrl, &model, &root, &dock)) {
            if (remote_call_current_success()) {
                // Dock app movement is optional. If this SpringBoard build
                // does not expose a canonical, self-consistent model, leave
                // the already-applied dock/grid sizing intact and skip before
                // retaining or mutating any icon state.
                printf("[SBC:DOCK] autofill skipped: canonical runtime unavailable; base layout remains applied\n");
                log_user("[WARN] Dock app autofill was skipped because SpringBoard's canonical icon model was unavailable. The base layout remains applied.\n");
                return true;
            }
            break;
        }
        if (!sbc_method_shape(dock, "insertIcon:atIndex:", '@', "@Q") ||
            !sbc_method_shape(dock, "allowsAddingIcon:", 'B', "@")) {
            printf("[SBC:DOCK] refused: dock mutation ABI is unsupported\n");
            break;
        }

        uint64_t dockCount = 0;
        uint64_t dockMax = 0;
        if (!sbc_read_count(dock, "numberOfIcons", &dockCount) ||
            !sbc_read_count(dock, "maxNumberOfIcons", &dockMax) ||
            dockCount > SBC_MAX_DOCK_MOVES || dockMax == 0) {
            printf("[SBC:DOCK] refused: invalid dock capacity\n");
            break;
        }
        uint64_t capacity = dockMax < (uint64_t)dockIcons
            ? dockMax : (uint64_t)dockIcons;
        if (dockCount > capacity) {
            printf("[SBC:DOCK] refused: dock already exceeds configured capacity\n");
            break;
        }

        originalDockCount = (size_t)dockCount;
        bool preflightOK = true;
        SBCIconSnapshot originalDockSnapshot = {0};
        if (!sbc_take_icon_snapshot(dock, &originalDockSnapshot) ||
            originalDockSnapshot.count != originalDockCount) {
            preflightOK = false;
        }
        for (size_t i = 0; preflightOK && i < originalDockCount; i++) {
            if (!sbc_icon_snapshot_at(&originalDockSnapshot, i,
                                      &originalDockIcons[i])) {
                preflightOK = false;
                break;
            }
        }
        sbc_release_icon_snapshot(&originalDockSnapshot);
        if (!preflightOK) break;

        NSMutableSet<NSString *> *seen =
            [NSMutableSet setWithCapacity:orderedBundleIDs.count];
        for (id value in orderedBundleIDs) {
            if (![value isKindOfClass:[NSString class]] ||
                [(NSString *)value length] == 0 || [seen containsObject:value]) {
                printf("[SBC:DOCK] refused: bundle selection is invalid or duplicated\n");
                preflightOK = false;
                break;
            }
            [seen addObject:value];
            const char *bundleID = [(NSString *)value UTF8String];
            if (!bundleID || !bundleID[0] ||
                strlen(bundleID) >= sizeof(pending[0].bundleID)) {
                preflightOK = false;
                break;
            }

            SBCApplicationPlacements placements = {0};
            if (!sbc_resolve_application_placements(root, dock,
                                                    bundleID, &placements)) {
                printf("[SBC:DOCK] refused: could not resolve concrete icons for %s\n",
                       bundleID);
                preflightOK = false;
                break;
            }
            sbc_log_application_placements(bundleID, &placements);

            if (placements.ambiguousCount != 0 ||
                placements.candidateCount > 1) {
                printf("[SBC:DOCK] refused: %s has duplicate direct placements\n",
                       bundleID);
                preflightOK = false;
                break;
            }
            if (placements.dockCount == 1) continue;
            if (placements.candidateCount != 1 ||
                placements.rootPageCount != 1) {
                printf("[SBC:DOCK] refused: %s does not have one unambiguous root-page icon\n",
                       bundleID);
                preflightOK = false;
                break;
            }

            uint64_t icon = placements.rootPageIcon;
            uint64_t sourceList = placements.rootPageList;
            // The resolver returns model-owned objects. Retain the concrete
            // pair immediately, before any later main-thread call can drain an
            // autorelease or rebuild the page model underneath preflight.
            if (!sbc_retain_main(icon)) {
                preflightOK = false;
                break;
            }
            if (!sbc_retain_main(sourceList)) {
                sbc_release_main(icon);
                preflightOK = false;
                break;
            }

            uint64_t sourceFolder = 0;
            uint64_t sourceCount = 0;
            uint64_t sourceMax = 0;
            if (!sbc_object_getter(sourceList, "folder", &sourceFolder) ||
                sourceFolder != root ||
                !sbc_root_contains_page(root, sourceList) ||
                !sbc_method_shape(sourceList, "insertIcon:atIndex:", '@', "@Q") ||
                !sbc_read_count(sourceList, "numberOfIcons", &sourceCount) ||
                !sbc_read_count(sourceList, "maxNumberOfIcons", &sourceMax)) {
                printf("[SBC:DOCK] refused: %s is not on a stable root page\n", bundleID);
                sbc_release_main(sourceList);
                sbc_release_main(icon);
                preflightOK = false;
                break;
            }

            uint64_t sourceIndex = placements.rootPageIconIndex;
            uint64_t indexedIcon = 0;
            bool dockAllows = false;
            size_t plannedFromSource = 1;
            for (size_t j = 0; j < pendingCount; j++) {
                if (pending[j].sourceList == sourceList) plannedFromSource++;
            }
            if (sourceCount == 0 || sourceCount > sourceMax ||
                sourceIndex >= sourceCount ||
                !sbc_icon_at_index(sourceList, sourceIndex, &indexedIcon) ||
                indexedIcon != icon ||
                plannedFromSource >= sourceCount ||
                !sbc_read_bool_object_arg(dock, "allowsAddingIcon:", icon,
                                          &dockAllows) || !dockAllows ||
                pendingCount >= SBC_MAX_DOCK_MOVES) {
                printf("[SBC:DOCK] refused: %s failed capacity/source preflight\n",
                       bundleID);
                sbc_release_main(sourceList);
                sbc_release_main(icon);
                preflightOK = false;
                break;
            }

            SBCDockPendingMove *move = &pending[pendingCount++];
            move->icon = icon;
            move->sourceList = sourceList;
            move->sourceIndex = sourceIndex;
            move->retained = true;
            snprintf(move->bundleID, sizeof(move->bundleID), "%s", bundleID);
        }
        if (!preflightOK) break;
        if (pendingCount > capacity - dockCount) {
            printf("[SBC:DOCK] refused: need=%zu free=%llu\n",
                   pendingCount, (unsigned long long)(capacity - dockCount));
            break;
        }
        if (pendingCount == 0) {
            applied = true;
            break;
        }

        bool beganState = sbc_begin_dock_state(model, root, dock);
        stateStarted = beganState;
        if (!beganState) {
            printf("[SBC:DOCK] refused: could not arm transient save state\n");
            sbc_release_empty_state_containers();
            break;
        }
        gSBCDockState.originalDockCount = originalDockCount;
        memcpy(gSBCDockState.originalDockIcons, originalDockIcons,
               originalDockCount * sizeof(originalDockIcons[0]));

        bool mutationOK = true;
        for (size_t i = 0; i < pendingCount; i++) {
            uint64_t sourceBefore = 0;
            uint64_t dockBefore = 0;
            if (!sbc_read_count(pending[i].sourceList, "numberOfIcons",
                                &sourceBefore) ||
                !sbc_read_count(dock, "numberOfIcons", &dockBefore)) {
                mutationOK = false;
                break;
            }
            uint64_t expectedSourceIndex = pending[i].sourceIndex;
            for (size_t j = 0; j < i; j++) {
                if (pending[j].sourceList == pending[i].sourceList &&
                    pending[j].sourceIndex < pending[i].sourceIndex &&
                    expectedSourceIndex > 0) {
                    expectedSourceIndex--;
                }
            }
            uint64_t currentSourceIcon = 0;
            bool exactSourceOK =
                sbc_icon_at_index(pending[i].sourceList,
                                  expectedSourceIndex,
                                  &currentSourceIcon) &&
                currentSourceIcon == pending[i].icon;
            if (dockBefore != originalDockCount + i || sourceBefore == 0 ||
                !exactSourceOK) {
                mutationOK = false;
                break;
            }

            SBCDockMove *record = &gSBCDockState.moves[gSBCDockState.moveCount++];
            record->icon = pending[i].icon;
            record->sourceList = pending[i].sourceList;
            record->sourceIndex = pending[i].sourceIndex;
            record->dockIndex = dockBefore;
            snprintf(record->bundleID, sizeof(record->bundleID), "%s",
                     pending[i].bundleID);
            record->active = true;
            pending[i].retained = false; // ownership transferred to the record

            (void)r_msg2_main(dock, "insertIcon:atIndex:",
                              record->icon, record->dockIndex, 0, 0);
            uint64_t sourceAfter = 0;
            uint64_t dockAfter = 0;
            SBCApplicationPlacements verification = {0};
            bool verificationReadsOK = remote_call_current_success() &&
                sbc_read_count(record->sourceList, "numberOfIcons", &sourceAfter) &&
                sbc_read_count(dock, "numberOfIcons", &dockAfter) &&
                sbc_resolve_application_placements(root, dock,
                                                    record->bundleID,
                                                    &verification);

            if (!verificationReadsOK || !remote_call_current_success() ||
                verification.ambiguousCount != 0 ||
                verification.candidateCount != 1 ||
                verification.dockCount != 1 ||
                verification.rootPageCount != 0 ||
                verification.dockIcon != record->icon ||
                verification.dockIconIndex != record->dockIndex ||
                sourceAfter + 1 != sourceBefore ||
                dockAfter != dockBefore + 1 ||
                !sbc_verify_dock_order(dock, originalDockIcons,
                                       originalDockCount, pending, i + 1)) {
                printf("[SBC:DOCK] move verification failed for %s\n",
                       pending[i].bundleID);
                mutationOK = false;
                break;
            }
            printf("[SBC:DOCK] appended %s at dock index %llu\n",
                   pending[i].bundleID,
                   (unsigned long long)record->dockIndex);
        }
        if (!mutationOK) break;

        // End the autosave suppression scope before asking the retained model
        // to persist.  Keep model/root/dock refs alive until the save call and
        // release all of them immediately afterward.
        bool assertionReleased = sbc_release_autosave_assertion();
        bool committed = sbc_commit_icon_state();
        bool released = sbc_discard_dock_state("durable save complete");
        applied = assertionReleased && committed && released &&
                  !sbcustomizer_has_remote_state();
        if (!applied) {
            printf("[SBC:DOCK] durable save/cleanup failed assertion=%d committed=%d released=%d\n",
                   assertionReleased ? 1 : 0, committed ? 1 : 0,
                   released ? 1 : 0);
        } else {
            printf("[SBC:DOCK] ordered dock moves committed permanently\n");
        }
    } while (0);

    sbc_release_pending_moves(pending, pendingCount);
    if (!applied && stateStarted) {
        // Exact reversal is intentionally not part of the one-shot contract.
        // Drop all ownership even when a partial mutation or save failed.
        bool released = sbc_discard_dock_state("apply did not complete");
        printf("[SBC:DOCK] apply failed; transient state released=%d\n",
               released ? 1 : 0);
    }
    return applied && !sbcustomizer_has_remote_state() &&
           remote_call_current_success();
}

bool sbcustomizer_apply_in_session(int dockIcons, int hsCols, int hsRows,
                                   bool hideLabels,
                                   NSArray<NSString *> *orderedDockBundleIDs)
{
    // Main-thread helpers expand into several internal ObjC calls. Applying
    // the global 50 ms settle to every one of those calls made SBC take many
    // seconds per page. Keep the main-thread routing for UIKit/model safety;
    // the explicit sleeps below remain the operation-level pacing.
    uint32_t previousSettleUS = r_settle_us(0);
    dockIcons = clamp(dockIcons, 4, 7);
    hsCols    = clamp(hsCols,    3, 7);
    hsRows    = clamp(hsRows,    4, 8);
    printf("[SBC] === entry === dock=%d hs=%dx%d hideLabels=%d\n",
           dockIcons, hsCols, hsRows, hideLabels);

    bool ok = false;
    do {
        if (sbcustomizer_has_remote_state() &&
            !sbc_discard_dock_state("prior apply cleanup")) {
            printf("[SBC:DOCK] prior transient dock state could not be released\n");
            break;
        }
        usleep(100000);
        uint64_t cls = r_class("SBIconController");
        if (!cls) { printf("[SBC] SBIconController missing\n"); break; }
        usleep(50000);

        uint64_t iconCtrl = r_msg2_main(cls, "sharedInstance", 0, 0, 0, 0);
        if (!iconCtrl) { printf("[SBC] +sharedInstance nil\n"); break; }
        printf("[SBC] iconCtrl=0x%llx\n", iconCtrl);

        patch_dock(iconCtrl, dockIcons);
        patch_homescreen_grid(iconCtrl, hsCols, hsRows, hideLabels);
        ok = remote_call_current_success() &&
             sbc_apply_ordered_dock_apps(iconCtrl, dockIcons,
                                         orderedDockBundleIDs ?: @[]);
    } while (0);

    bool result = ok && remote_call_current_success();
    r_settle_us(previousSettleUS);
    return result;
}
