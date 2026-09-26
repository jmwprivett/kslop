#import <Foundation/Foundation.h>
#import <QuartzCore/QuartzCore.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_CHICLET_OUTPUT_TOKEN
#define CND_CHICLET_OUTPUT_TOKEN ""
#endif

#ifndef CND_CHICLET_REPORT_PATH
#define CND_CHICLET_REPORT_PATH \
    "/var/tmp/cyanide-spotlight-chiclet-patch.log"
#endif

#ifndef CND_CHICLET_THEMED_ONLY
#define CND_CHICLET_THEMED_ONLY 1
#endif

#ifndef CND_CHICLET_THEME_MARKER
#define CND_CHICLET_THEME_MARKER "CNDThemeIcon.v1"
#endif

static const char *const CNDReportPath = CND_CHICLET_REPORT_PATH;
static const uint64_t CNDIconRenderingPatchVMAddress = 0x1b0d5065cULL;
static const uint32_t CNDExpectedInstruction = 0x52800028U; /* mov w8, #1 */
static const uint32_t CNDPatchInstruction = 0x52800008U;    /* mov w8, #0 */
static const uint8_t CNDExpectedIconRenderingUUID[16] = {
    0x81, 0xcb, 0x5b, 0xe9, 0xb5, 0xda, 0x35, 0x51,
    0x90, 0xfd, 0x90, 0xd6, 0xe1, 0x8d, 0x56, 0x9a,
};

typedef id (*CNDInitFromSerializedDataIMP)(id, SEL, id, id, NSError **);
typedef id (*CNDIconLayerInitWithDataIMP)(id, SEL, id, NSError **);
typedef id (*CNDIconLayerInitWithFinalizedIconIMP)(id, SEL, id);
typedef void (*CNDIconLayerLayoutIMP)(id, SEL);

extern kern_return_t mach_vm_region_recurse(
    vm_map_t targetTask, mach_vm_address_t *address,
    mach_vm_size_t *size, natural_t *depth,
    vm_region_recurse_info_t info, mach_msg_type_number_t *infoCount);

static CNDInitFromSerializedDataIMP gOriginalInitFromSerializedData;
static CNDIconLayerInitWithDataIMP gOriginalIconLayerInitWithData;
static CNDIconLayerInitWithFinalizedIconIMP
    gOriginalIconLayerInitWithFinalizedIcon;
static CNDIconLayerLayoutIMP gOriginalIconLayerLayout;
static unsigned gDeserializationCount;
static unsigned gThemedLayerTreeCount;
static char gCNDThemedObjectAssociationKey;
static char gCNDThemedImageAssociationKey;

static void CNDLog(const char *format, ...)
{
    int descriptor = open(CNDReportPath, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (descriptor < 0) return;
    va_list arguments;
    va_start(arguments, format);
    vdprintf(descriptor, format, arguments);
    va_end(arguments);
    close(descriptor);
}

static bool CNDHasSuffix(const char *value, const char *suffix)
{
    if (!value || !suffix) return false;
    size_t valueLength = strlen(value);
    size_t suffixLength = strlen(suffix);
    return valueLength >= suffixLength &&
        memcmp(value + valueLength - suffixLength, suffix, suffixLength) == 0;
}

static bool CNDImageUUID(const struct mach_header_64 *header,
                         uint8_t result[16])
{
    if (!header || header->magic != MH_MAGIC_64) return false;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    for (uint32_t index = 0; index < header->ncmds; index++) {
        const struct load_command *command =
            (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(*command)) return false;
        if (command->cmd == LC_UUID &&
            command->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid =
                (const struct uuid_command *)command;
            memcpy(result, uuid->uuid, 16U);
            return true;
        }
        cursor += command->cmdsize;
    }
    return false;
}

static const struct mach_header_64 *CNDIconRenderingHeader(
    intptr_t *slideOut, const char **pathOut)
{
    uint32_t count = _dyld_image_count();
    for (uint32_t index = 0; index < count; index++) {
        const char *path = _dyld_get_image_name(index);
        if (!CNDHasSuffix(
                path,
                "/System/Library/PrivateFrameworks/IconRendering.framework/"
                "IconRendering")) {
            continue;
        }
        const struct mach_header *header = _dyld_get_image_header(index);
        if (!header || header->magic != MH_MAGIC_64) return NULL;
        if (slideOut) *slideOut = _dyld_get_image_vmaddr_slide(index);
        if (pathOut) *pathOut = path;
        return (const struct mach_header_64 *)header;
    }
    return NULL;
}

static bool CNDRegionInfo(mach_vm_address_t address,
                          vm_region_submap_info_data_64_t *infoOut,
                          mach_vm_address_t *startOut,
                          mach_vm_size_t *sizeOut)
{
    mach_vm_address_t start = address;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info = {0};
    kern_return_t result = KERN_FAILURE;
    do {
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        result = mach_vm_region_recurse(
            mach_task_self(), &start, &size, &depth,
            (vm_region_recurse_info_t)&info, &count);
        if (result != KERN_SUCCESS || address < start ||
            address >= start + size) {
            return false;
        }
        if (info.is_submap) {
            depth++;
            start = address;
        }
    } while (info.is_submap);
    if (result != KERN_SUCCESS) {
        return false;
    }
    if (infoOut) *infoOut = info;
    if (startOut) *startOut = start;
    if (sizeOut) *sizeOut = size;
    return true;
}

static bool CNDApplyPrivateInstructionPatch(void)
{
    intptr_t slide = 0;
    const char *path = NULL;
    const struct mach_header_64 *header =
        CNDIconRenderingHeader(&slide, &path);
    uint8_t uuid[16] = {0};
    if (!header || !CNDImageUUID(header, uuid) ||
        memcmp(uuid, CNDExpectedIconRenderingUUID, sizeof(uuid)) != 0) {
        CNDLog("[CND_CHICLET_PATCH] PATCH_REJECTED reason=image-or-uuid "
               "header=%p path=%s\n", header, path ?: "-");
        return false;
    }

    mach_vm_address_t target =
        (mach_vm_address_t)((int64_t)CNDIconRenderingPatchVMAddress + slide);
    uint32_t before = *(const volatile uint32_t *)(uintptr_t)target;
    if (before != CNDExpectedInstruction) {
        CNDLog("[CND_CHICLET_PATCH] PATCH_REJECTED reason=instruction "
               "target=0x%llx observed=0x%08x expected=0x%08x\n",
               target, before, CNDExpectedInstruction);
        return false;
    }

    vm_region_submap_info_data_64_t beforeInfo = {0};
    mach_vm_address_t regionStart = 0;
    mach_vm_size_t regionSize = 0;
    if (!CNDRegionInfo(target, &beforeInfo, &regionStart, &regionSize) ||
        !(beforeInfo.protection & VM_PROT_EXECUTE)) {
        CNDLog("[CND_CHICLET_PATCH] PATCH_REJECTED reason=region "
               "target=0x%llx\n", target);
        return false;
    }

    vm_size_t pageSize = 0;
    if (host_page_size(mach_host_self(), &pageSize) != KERN_SUCCESS ||
        pageSize == 0 || (pageSize & (pageSize - 1U)) != 0) {
        CNDLog("[CND_CHICLET_PATCH] PATCH_REJECTED reason=page-size\n");
        return false;
    }
    mach_vm_address_t page = target & ~((mach_vm_address_t)pageSize - 1U);

    /* VM_PROT_COPY asks Mach for a process-private COW shadow instead of
     * changing the shared-cache page in place.  This is the property the
     * eventual kernel-only implementation must reproduce explicitly. */
    kern_return_t writable = vm_protect(
        mach_task_self(), (vm_address_t)page, pageSize, FALSE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (writable != KERN_SUCCESS) {
        CNDLog("[CND_CHICLET_PATCH] PATCH_REJECTED reason=private-cow "
               "kr=%d target=0x%llx protection=%x max=%x shared=%d\n",
               writable, target, beforeInfo.protection,
               beforeInfo.max_protection, beforeInfo.share_mode);
        return false;
    }

    *(volatile uint32_t *)(uintptr_t)target = CNDPatchInstruction;
    sys_icache_invalidate((void *)(uintptr_t)target, sizeof(uint32_t));
    kern_return_t executable = vm_protect(
        mach_task_self(), (vm_address_t)page, pageSize, FALSE,
        VM_PROT_READ | VM_PROT_EXECUTE);
    uint32_t after = *(const volatile uint32_t *)(uintptr_t)target;
    if (executable != KERN_SUCCESS || after != CNDPatchInstruction) {
        kern_return_t rollbackWritable = vm_protect(
            mach_task_self(), (vm_address_t)page, pageSize, FALSE,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (rollbackWritable == KERN_SUCCESS) {
            *(volatile uint32_t *)(uintptr_t)target = CNDExpectedInstruction;
            sys_icache_invalidate((void *)(uintptr_t)target,
                                  sizeof(uint32_t));
            (void)vm_protect(
                mach_task_self(), (vm_address_t)page, pageSize, FALSE,
                beforeInfo.protection);
        }
        CNDLog("[CND_CHICLET_PATCH] PATCH_REJECTED reason=readback-or-rx "
               "rxKr=%d rollbackWriteKr=%d observed=0x%08x\n",
               executable, rollbackWritable, after);
        return false;
    }

    vm_region_submap_info_data_64_t afterInfo = {0};
    bool haveAfterInfo = CNDRegionInfo(
        target, &afterInfo, NULL, NULL);
    CNDLog("[CND_CHICLET_PATCH] PATCH_ACTIVE image=%s slide=0x%llx "
           "target=0x%llx before=0x%08x after=0x%08x page=%u "
           "region=0x%llx+0x%llx beforeProt=%x/%x beforeShared=%d "
           "afterProt=%x/%x afterShared=%d\n",
           path, (uint64_t)slide, target, before, after, pageSize,
           regionStart, regionSize, beforeInfo.protection,
           beforeInfo.max_protection, beforeInfo.share_mode,
           haveAfterInfo ? afterInfo.protection : 0,
           haveAfterInfo ? afterInfo.max_protection : 0,
           haveAfterInfo ? afterInfo.share_mode : -1);
    return true;
}

static bool CNDValidateUnmodifiedInstruction(void)
{
    intptr_t slide = 0;
    const char *path = NULL;
    const struct mach_header_64 *header =
        CNDIconRenderingHeader(&slide, &path);
    uint8_t uuid[16] = {0};
    if (!header || !CNDImageUUID(header, uuid) ||
        memcmp(uuid, CNDExpectedIconRenderingUUID, sizeof(uuid)) != 0) {
        CNDLog("[CND_CHICLET_PATCH] SCOPE_REJECTED reason=image-or-uuid "
               "header=%p path=%s\n", header, path ?: "-");
        return false;
    }
    mach_vm_address_t target =
        (mach_vm_address_t)((int64_t)CNDIconRenderingPatchVMAddress + slide);
    uint32_t instruction = *(const volatile uint32_t *)(uintptr_t)target;
    if (instruction != CNDExpectedInstruction) {
        CNDLog("[CND_CHICLET_PATCH] SCOPE_REJECTED reason=instruction "
               "target=0x%llx observed=0x%08x expected=0x%08x\n",
               target, instruction, CNDExpectedInstruction);
        return false;
    }
    CNDLog("[CND_CHICLET_PATCH] SCOPE_VALIDATED image=%s slide=0x%llx "
           "target=0x%llx instruction=0x%08x marker=%s\n",
           path, (uint64_t)slide, target, instruction,
           CND_CHICLET_THEME_MARKER);
    return true;
}

static bool CNDSerializedDataContainsThemeMarker(id object,
                                                 NSUInteger *lengthOut)
{
    if (![object isKindOfClass:NSData.class]) return false;
    NSData *data = object;
    const uint8_t *bytes = data.bytes;
    NSUInteger length = data.length;
    const uint8_t marker[] = CND_CHICLET_THEME_MARKER;
    const NSUInteger markerLength = sizeof(marker) - 1U;
    if (lengthOut) *lengthOut = length;
    if (!bytes || markerLength == 0U || length < markerLength) return false;
    for (NSUInteger offset = 0; offset <= length - markerLength; offset++) {
        if (bytes[offset] == marker[0] &&
            !memcmp(bytes + offset, marker, markerLength)) {
            return true;
        }
    }
    return false;
}

static bool CNDObjectIsThemed(id object)
{
    return object && objc_getAssociatedObject(
        object, &gCNDThemedObjectAssociationKey) != nil;
}

static void CNDMarkObjectThemed(id object)
{
    if (!object) return;
    objc_setAssociatedObject(
        object, &gCNDThemedObjectAssociationKey, @YES,
        OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static id CNDThemedImageForObject(id object)
{
    return object ? objc_getAssociatedObject(
        object, &gCNDThemedImageAssociationKey) : nil;
}

static void CNDAssociateThemedImage(id object, id image)
{
    if (!object || !image) return;
    objc_setAssociatedObject(
        object, &gCNDThemedImageAssociationKey, image,
        OBJC_ASSOCIATION_RETAIN_NONATOMIC);
}

static void CNDPrepareThemedImage(id finalizedIcon)
{
    Class configurationClass = objc_getClass("ICRGlobalConfiguration");
    id configuration = configurationClass
        ? [[configurationClass alloc] init] : nil;
    SEL selector = sel_registerName(
        "renderedFullBleedIconWithConfiguration:"
        "excludeChicletSpecularHighlights:");
    Method method = finalizedIcon
        ? class_getInstanceMethod(object_getClass(finalizedIcon), selector)
        : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!configuration || !types ||
        strcmp(types, "^{CGImage=}28@0:8@16B24") != 0) {
        CNDLog("[CND_CHICLET_PATCH] FLAT_IMAGE_REJECTED reason=abi "
               "configuration=%p types=%s\n", configuration,
               types ?: "-");
        return;
    }
    CGImageRef image =
        ((CGImageRef (*)(id, SEL, id, BOOL))objc_msgSend)(
            finalizedIcon, selector, configuration, YES);
    size_t width = image ? CGImageGetWidth(image) : 0U;
    size_t height = image ? CGImageGetHeight(image) : 0U;
    if (!image || width == 0U || height == 0U) {
        CNDLog("[CND_CHICLET_PATCH] FLAT_IMAGE_REJECTED reason=render "
               "image=%p pixels=%zux%zu\n", image, width, height);
        return;
    }
    CNDAssociateThemedImage(finalizedIcon, (__bridge id)image);
    CNDLog("[CND_CHICLET_PATCH] FLAT_IMAGE_READY finalized=%p image=%p "
           "pixels=%zux%zu excludeSpecular=1\n",
           finalizedIcon, image, width, height);
}

static void CNDInstallFlatThemedSurface(CALayer *layer)
{
    id imageObject = CNDThemedImageForObject(layer);
    CGImageRef image = imageObject
        ? (__bridge CGImageRef)imageObject : NULL;
    if (!image) return;
    NSArray<CALayer *> *children = [layer.sublayers copy];
    [CATransaction begin];
    [CATransaction setDisableActions:YES];
    for (CALayer *child in children) {
        [child removeFromSuperlayer];
    }
    layer.contents = imageObject;
    layer.contentsGravity = kCAGravityResize;
    double pointWidth = layer.bounds.size.width;
    double scale = pointWidth > 0.0
        ? (double)CGImageGetWidth(image) / pointWidth : 1.0;
    layer.contentsScale = scale > 0.0 ? scale : 1.0;
    layer.opaque = NO;
    layer.masksToBounds = NO;
    layer.cornerRadius = 0.0;
    layer.borderWidth = 0.0;
    layer.backgroundColor = NULL;
    layer.shadowOpacity = 0.0f;
    [CATransaction commit];
    CNDLog("[CND_CHICLET_PATCH] FLAT_SURFACE_APPLIED layer=%p/%s "
           "pixels=%zux%zu points=%.2fx%.2f scale=%.3f "
           "removedChildren=%lu\n", layer,
           class_getName(object_getClass(layer)), CGImageGetWidth(image),
           CGImageGetHeight(image), layer.bounds.size.width,
           layer.bounds.size.height, layer.contentsScale,
           (unsigned long)children.count);
}

static void CNDLogLayerTree(CALayer *layer, unsigned depth)
{
    if (!layer || depth > 5U) return;
    CGColorRef background = layer.backgroundColor;
    CGColorRef border = layer.borderColor;
    id contents = layer.contents;
    NSArray<CALayer *> *sublayers = layer.sublayers;
    CNDLog("[CND_CHICLET_PATCH] LAYER depth=%u object=%p class=%s "
           "name=%s bounds=%.2f,%.2f,%.2f,%.2f opacity=%.3f hidden=%d "
           "opaque=%d masks=%d corner=%.3f border=%.3f/%p/%.3f "
           "background=%p/%.3f shadow=%.3f/%.3f contents=%p/%s "
           "filters=%lu sublayers=%lu\n",
           depth, layer, class_getName(object_getClass(layer)),
           layer.name.UTF8String ?: "-", layer.bounds.origin.x,
           layer.bounds.origin.y, layer.bounds.size.width,
           layer.bounds.size.height, layer.opacity, layer.hidden,
           layer.opaque, layer.masksToBounds, layer.cornerRadius,
           layer.borderWidth, border,
           border ? CGColorGetAlpha(border) : 0.0, background,
           background ? CGColorGetAlpha(background) : 0.0,
           layer.shadowOpacity, layer.shadowRadius,
           (__bridge void *)contents,
           contents ? class_getName(object_getClass(contents)) : "-",
           (unsigned long)layer.filters.count,
           (unsigned long)sublayers.count);
    NSUInteger cap = MIN(sublayers.count, 32U);
    for (NSUInteger index = 0; index < cap; index++) {
        CNDLogLayerTree(sublayers[index], depth + 1U);
    }
}

static void CNDLogThemedLayerTree(id object, const char *event)
{
    if (!CNDObjectIsThemed(object) || ![object isKindOfClass:CALayer.class]) {
        return;
    }
    unsigned count = __atomic_add_fetch(
        &gThemedLayerTreeCount, 1U, __ATOMIC_RELAXED);
    if (count > 12U) return;
    CNDLog("[CND_CHICLET_PATCH] LAYER_TREE event=%s count=%u root=%p/%s\n",
           event, count, object, class_getName(object_getClass(object)));
    CNDLogLayerTree(object, 0U);
}

static id CNDObservedInitFromSerializedData(id self, SEL selector,
                                            id data, id device,
                                            NSError **error)
{
    NSUInteger serializedLength = 0U;
    bool themed = CNDSerializedDataContainsThemeMarker(
        data, &serializedLength);
    id result = gOriginalInitFromSerializedData
        ? gOriginalInitFromSerializedData(self, selector, data, device, error)
        : nil;
    if (result && object_getClass(result) ==
            objc_getClass("ICRFinalizedIcon")) {
        uint8_t *visibleAddress = (uint8_t *)(void *)result + 0xb8U;
        uint8_t before = *visibleAddress;
        if (CND_CHICLET_THEMED_ONLY && themed && before == 1U) {
            *visibleAddress = 0U;
        }
        if (themed) CNDMarkObjectThemed(result);
        if (themed) CNDPrepareThemedImage(result);
        uint8_t after = *visibleAddress;
        unsigned count = __atomic_add_fetch(
            &gDeserializationCount, 1U, __ATOMIC_RELAXED);
        if (count <= 256U) {
            CNDLog("[CND_CHICLET_PATCH] DESERIALIZED count=%u object=%p "
                   "bytes=%lu themed=%d chicletBefore=%u chicletAfter=%u\n",
                   count, result, (unsigned long)serializedLength, themed,
                   before, after);
        }
    }
    return result;
}

static id CNDObservedIconLayerInitWithData(id self, SEL selector,
                                           id data, NSError **error)
{
    bool themed = CNDSerializedDataContainsThemeMarker(data, NULL);
    id result = gOriginalIconLayerInitWithData
        ? gOriginalIconLayerInitWithData(self, selector, data, error) : nil;
    if (themed && result) CNDMarkObjectThemed(result);
    CNDLogThemedLayerTree(result, "initWithData-return");
    return result;
}

static id CNDObservedIconLayerInitWithFinalizedIcon(id self, SEL selector,
                                                    id finalizedIcon)
{
    bool themed = CNDObjectIsThemed(finalizedIcon);
    id themedImage = CNDThemedImageForObject(finalizedIcon);
    id result = gOriginalIconLayerInitWithFinalizedIcon
        ? gOriginalIconLayerInitWithFinalizedIcon(
              self, selector, finalizedIcon) : nil;
    if (themed && result) {
        CNDMarkObjectThemed(result);
        CNDAssociateThemedImage(result, themedImage);
    }
    CNDLogThemedLayerTree(result, "initWithFinalizedIcon-return");
    return result;
}

static void CNDObservedIconLayerLayout(id self, SEL selector)
{
    if (gOriginalIconLayerLayout) {
        gOriginalIconLayerLayout(self, selector);
    }
    CNDInstallFlatThemedSurface(self);
    CNDLogThemedLayerTree(self, "layoutSublayers-return");
}

static bool CNDInstallReadbackObserver(void)
{
    Class cls = objc_getClass("ICRFinalizedIcon");
    SEL selector = sel_registerName("initFromSerializedData:device:error:");
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!method || !types || strcmp(types, "@40@0:8@16@24^@32") != 0) {
        CNDLog("[CND_CHICLET_PATCH] OBSERVER_REJECTED types=%s\n",
               types ?: "-");
        return false;
    }
    gOriginalInitFromSerializedData =
        (CNDInitFromSerializedDataIMP)method_getImplementation(method);
    method_setImplementation(method, (IMP)CNDObservedInitFromSerializedData);
    CNDLog("[CND_CHICLET_PATCH] OBSERVER_READY class=ICRFinalizedIcon "
           "selector=initFromSerializedData:device:error:\n");
    return true;
}

static bool CNDInstallLayerObserver(void)
{
    Class cls = objc_getClass("ICRIconLayer");
    SEL dataSelector = sel_registerName("initWithData:error:");
    SEL finalizedSelector = sel_registerName("initWithFinalizedIcon:");
    SEL layoutSelector = sel_registerName("layoutSublayers");
    Method dataMethod = cls
        ? class_getInstanceMethod(cls, dataSelector) : NULL;
    Method finalizedMethod = cls
        ? class_getInstanceMethod(cls, finalizedSelector) : NULL;
    Method layoutMethod = cls
        ? class_getInstanceMethod(cls, layoutSelector) : NULL;
    const char *dataTypes = dataMethod
        ? method_getTypeEncoding(dataMethod) : NULL;
    const char *finalizedTypes = finalizedMethod
        ? method_getTypeEncoding(finalizedMethod) : NULL;
    const char *layoutTypes = layoutMethod
        ? method_getTypeEncoding(layoutMethod) : NULL;
    if (!dataTypes || strcmp(dataTypes, "@32@0:8@16^@24") != 0 ||
        !finalizedTypes || strcmp(finalizedTypes, "@24@0:8@16") != 0 ||
        !layoutTypes || strcmp(layoutTypes, "v16@0:8") != 0) {
        CNDLog("[CND_CHICLET_PATCH] LAYER_OBSERVER_REJECTED "
               "data=%s finalized=%s layout=%s\n",
               dataTypes ?: "-", finalizedTypes ?: "-",
               layoutTypes ?: "-");
        return false;
    }
    gOriginalIconLayerInitWithData =
        (CNDIconLayerInitWithDataIMP)method_getImplementation(dataMethod);
    gOriginalIconLayerInitWithFinalizedIcon =
        (CNDIconLayerInitWithFinalizedIconIMP)
            method_getImplementation(finalizedMethod);
    gOriginalIconLayerLayout =
        (CNDIconLayerLayoutIMP)method_getImplementation(layoutMethod);
    method_setImplementation(
        dataMethod, (IMP)CNDObservedIconLayerInitWithData);
    method_setImplementation(
        finalizedMethod, (IMP)CNDObservedIconLayerInitWithFinalizedIcon);
    method_setImplementation(layoutMethod, (IMP)CNDObservedIconLayerLayout);
    CNDLog("[CND_CHICLET_PATCH] LAYER_OBSERVER_READY "
           "class=ICRIconLayer\n");
    return true;
}

__attribute__((constructor))
static void CNDSpotlightChicletPatchStart(void)
{
    if (CND_CHICLET_OUTPUT_TOKEN[0]) {
        void *sandbox = dlopen("/usr/lib/system/libsystem_sandbox.dylib",
                               RTLD_LAZY | RTLD_LOCAL);
        int (*consume)(const char *) = sandbox
            ? (int (*)(const char *))dlsym(
                  sandbox, "sandbox_extension_consume")
            : NULL;
        if (consume) (void)consume(CND_CHICLET_OUTPUT_TOKEN);
    }
    unlink(CNDReportPath);
    void *iconRendering = dlopen(
        "/System/Library/PrivateFrameworks/IconRendering.framework/"
        "IconRendering", RTLD_NOW | RTLD_LOCAL);
    if (!iconRendering) {
        CNDLog("[CND_CHICLET_PATCH] LOAD_REJECTED framework=IconRendering "
               "error=%s\n", dlerror() ?: "-");
        return;
    }
    if (CND_CHICLET_THEMED_ONLY) {
        if (!CNDValidateUnmodifiedInstruction()) return;
    } else if (!CNDApplyPrivateInstructionPatch()) {
        return;
    }
    if (!CNDInstallReadbackObserver()) return;
    if (!CNDInstallLayerObserver()) return;
    CNDLog("[CND_CHICLET_PATCH] READY pid=%d mode=%s marker=%s\n",
           getpid(), CND_CHICLET_THEMED_ONLY ? "themed-only" : "global",
           CND_CHICLET_THEME_MARKER);
}
