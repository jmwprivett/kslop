#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import <CoreGraphics/CoreGraphics.h>
#import <objc/message.h>
#import <objc/runtime.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef CND_PDF_TRACE_QUERY
#define CND_PDF_TRACE_QUERY "eBay"
#endif

#ifndef CND_PDF_TRACE_SET_QUERY
#define CND_PDF_TRACE_SET_QUERY 1
#endif

static const char *const CNDReportPath =
    "/var/tmp/cyanide-spotlight-pdf-reachability.log";
static const char *const CNDCanarySubject =
    "CND_SPOTLIGHT_PDF_CANARY_V1";

static int gCNDFD = -1;
static id (*gCNDOriginalPDFInit)(id, SEL, void *, int64_t);
static CGImageRef (*gCNDOriginalPDFRender)(id, SEL, double);
static CGImageRef (*gCNDOriginalVectorRaster)(id, SEL, double, CGSize);
static unsigned gCNDCanaryInitCount;
static unsigned gCNDCanaryRenderCount;
static unsigned gCNDCanaryVectorCount;
#if CND_PDF_TRACE_SET_QUERY
static unsigned gCNDQueryAttempt;
static bool gCNDQuerySet;
#endif

static void CNDLog(const char *format, ...)
    __attribute__((format(printf, 1, 2)));

static void CNDLog(const char *format, ...)
{
    if (gCNDFD < 0) return;
    char line[4096] = {0};
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (length <= 0) return;
    size_t amount = MIN((size_t)length, sizeof(line) - 1U);
    (void)write(gCNDFD, line, amount);
    (void)fsync(gCNDFD);
}

static CGPDFDocumentRef CNDDocumentForObject(id object)
{
    if (!object) return NULL;
    SEL selector = sel_registerName("pdfDocument");
    Method method = class_getInstanceMethod(object_getClass(object),
                                             selector);
    if (!method || method_getNumberOfArguments(method) != 2U) return NULL;
    return ((CGPDFDocumentRef (*)(id, SEL))objc_msgSend)(object, selector);
}

static NSString *CNDDocumentSubject(CGPDFDocumentRef document)
{
    CGPDFDictionaryRef info = document ? CGPDFDocumentGetInfo(document)
                                       : NULL;
    CGPDFStringRef value = NULL;
    if (!info || !CGPDFDictionaryGetString(info, "Subject", &value) ||
        !value) {
        return nil;
    }
    CFStringRef text = CGPDFStringCopyTextString(value);
    return CFBridgingRelease(text);
}

static bool CNDIsCanary(id object, NSString **subjectOut,
                        CGRect *mediaBoxOut)
{
    CGPDFDocumentRef document = CNDDocumentForObject(object);
    NSString *subject = CNDDocumentSubject(document);
    CGPDFPageRef page = document && CGPDFDocumentGetNumberOfPages(document)
        ? CGPDFDocumentGetPage(document, 1U) : NULL;
    CGRect mediaBox = page
        ? CGPDFPageGetBoxRect(page, kCGPDFMediaBox) : CGRectZero;
    if (subjectOut) *subjectOut = subject;
    if (mediaBoxOut) *mediaBoxOut = mediaBox;
    return [subject isEqualToString:@"CND_SPOTLIGHT_PDF_CANARY_V1"];
}

static id CNDObservedPDFInit(id self, SEL command, void *header,
                             int64_t version)
{
    id result = gCNDOriginalPDFInit(self, command, header, version);
    NSString *subject = nil;
    CGRect mediaBox = CGRectZero;
    bool canary = CNDIsCanary(result, &subject, &mediaBox);
    CNDLog("[CND_PDF_REACH] PDF_INIT object=%p/%s header=%p version=%lld "
           "subject=%s mediaBox=%.2f,%.2f,%.2f,%.2f canary=%d\n",
           (__bridge void *)result,
           result ? class_getName(object_getClass(result)) : "-", header,
           (long long)version, subject.UTF8String ?: "-",
           mediaBox.origin.x, mediaBox.origin.y,
           mediaBox.size.width, mediaBox.size.height, canary);
    if (canary) {
        gCNDCanaryInitCount++;
        CNDLog("[CND_PDF_REACH] CANARY_PDF_INIT count=%u pid=%d\n",
               gCNDCanaryInitCount, getpid());
    }
    return result;
}

static CGImageRef CNDObservedPDFRender(id self, SEL command, double scale)
{
    NSString *subject = nil;
    CGRect mediaBox = CGRectZero;
    bool canary = CNDIsCanary(self, &subject, &mediaBox);
    CGImageRef image = gCNDOriginalPDFRender(self, command, scale);
    CNDLog("[CND_PDF_REACH] PDF_RENDER object=%p/%s subject=%s "
           "scale=%.3f pixels=%zux%zu canary=%d\n",
           (__bridge void *)self, class_getName(object_getClass(self)),
           subject.UTF8String ?: "-", scale,
           image ? CGImageGetWidth(image) : 0U,
           image ? CGImageGetHeight(image) : 0U, canary);
    if (canary) {
        gCNDCanaryRenderCount++;
        CNDLog("[CND_PDF_REACH] CANARY_PDF_RENDER count=%u pid=%d "
               "mediaBox=%.2fx%.2f\n", gCNDCanaryRenderCount, getpid(),
               mediaBox.size.width, mediaBox.size.height);
    }
    return image;
}

static CGImageRef CNDObservedVectorRaster(id self, SEL command,
                                          double scale, CGSize targetSize)
{
    NSString *subject = nil;
    CGRect mediaBox = CGRectZero;
    bool canary = CNDIsCanary(self, &subject, &mediaBox);
    CGImageRef image = gCNDOriginalVectorRaster(
        self, command, scale, targetSize);
    CNDLog("[CND_PDF_REACH] VECTOR_RASTER object=%p/%s subject=%s "
           "scale=%.3f target=%.2fx%.2f pixels=%zux%zu canary=%d\n",
           (__bridge void *)self, class_getName(object_getClass(self)),
           subject.UTF8String ?: "-", scale,
           targetSize.width, targetSize.height,
           image ? CGImageGetWidth(image) : 0U,
           image ? CGImageGetHeight(image) : 0U, canary);
    if (canary) {
        gCNDCanaryVectorCount++;
        CNDLog("[CND_PDF_REACH] CANARY_VECTOR_RASTER count=%u pid=%d\n",
               gCNDCanaryVectorCount, getpid());
    }
    return image;
}

static bool CNDInstallObjectHook(const char *className,
                                 const char *selectorName,
                                 IMP replacement, IMP *originalOut,
                                 unsigned expectedArguments)
{
    Class cls = objc_getClass(className);
    SEL selector = sel_registerName(selectorName);
    Method method = cls ? class_getInstanceMethod(cls, selector) : NULL;
    const char *types = method ? method_getTypeEncoding(method) : NULL;
    if (!method || method_getNumberOfArguments(method) != expectedArguments ||
        !types) {
        CNDLog("[CND_PDF_REACH] HOOK_REJECTED class=%s selector=%s "
               "method=%p args=%u types=%s\n", className, selectorName,
               method, method ? method_getNumberOfArguments(method) : 0U,
               types ?: "-");
        return false;
    }
    IMP original = method_getImplementation(method);
    if (!original) return false;
    method_setImplementation(method, replacement);
    *originalOut = original;
    CNDLog("[CND_PDF_REACH] HOOK_INSTALLED class=%s selector=%s "
           "types=%s original=%p replacement=%p\n", className,
           selectorName, types, original, replacement);
    return true;
}

#if CND_PDF_TRACE_SET_QUERY
static UITextField *CNDFindTextField(UIView *view)
{
    if ([view isKindOfClass:UITextField.class]) return (UITextField *)view;
    for (UIView *child in view.subviews) {
        UITextField *field = CNDFindTextField(child);
        if (field) return field;
    }
    return nil;
}

static NSArray<UIWindow *> *CNDWindows(void)
{
    NSMutableArray<UIWindow *> *windows = [NSMutableArray array];
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:UIWindowScene.class]) {
            [windows addObjectsFromArray:((UIWindowScene *)scene).windows];
        }
    }
    return windows;
}

static void CNDTrySetQuery(void)
{
    if (gCNDQuerySet) return;
    gCNDQueryAttempt++;
    UITextField *field = nil;
    NSArray<UIWindow *> *windows = CNDWindows();
    for (UIWindow *window in windows) {
        field = CNDFindTextField(window);
        if (field) break;
    }
    if (!field) {
        if (gCNDQueryAttempt == 1U || gCNDQueryAttempt % 10U == 0U) {
            CNDLog("[CND_PDF_REACH] QUERY_WAIT attempt=%u windows=%lu\n",
                   gCNDQueryAttempt,
                   (unsigned long)windows.count);
        }
        if (gCNDQueryAttempt < 120U) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                         (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ CNDTrySetQuery(); });
        }
        return;
    }
    gCNDQuerySet = true;
    field.text = @"";
    [field sendActionsForControlEvents:UIControlEventEditingChanged];
    [NSNotificationCenter.defaultCenter
        postNotificationName:UITextFieldTextDidChangeNotification
                      object:field];
    CNDLog("[CND_PDF_REACH] QUERY_CLEAR field=%p/%s attempt=%u\n",
           (__bridge void *)field, class_getName(object_getClass(field)),
           gCNDQueryAttempt);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                 (int64_t)(0.35 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        field.text = @CND_PDF_TRACE_QUERY;
        [field sendActionsForControlEvents:UIControlEventEditingChanged];
        [NSNotificationCenter.defaultCenter
            postNotificationName:UITextFieldTextDidChangeNotification
                          object:field];
        CNDLog("[CND_PDF_REACH] QUERY_SET field=%p/%s text=%s attempt=%u\n",
               (__bridge void *)field,
               class_getName(object_getClass(field)),
               field.text.UTF8String ?: "-", gCNDQueryAttempt);
    });
}
#endif

static void *CNDBootstrap(void *context)
{
    (void)context;
    @autoreleasepool {
        void *coreUI = dlopen(
            "/System/Library/PrivateFrameworks/CoreUI.framework/CoreUI",
            RTLD_NOW | RTLD_LOCAL);
        CNDLog("[CND_PDF_REACH] LOAD CoreUI=%p error=%s\n", coreUI,
               coreUI ? "-" : (dlerror() ?: "-"));
        unsigned hooks = 0U;
        hooks += CNDInstallObjectHook(
            "_CUIThemePDFRendition", "_initWithCSIHeader:version:",
            (IMP)CNDObservedPDFInit, (IMP *)&gCNDOriginalPDFInit, 4U);
        hooks += CNDInstallObjectHook(
            "_CUIThemePDFRendition",
            "createImageFromPDFRenditionWithScale:",
            (IMP)CNDObservedPDFRender, (IMP *)&gCNDOriginalPDFRender, 3U);
        hooks += CNDInstallObjectHook(
            "CUINamedVectorPDFImage",
            "rasterizeImageUsingScaleFactor:forTargetSize:",
            (IMP)CNDObservedVectorRaster, (IMP *)&gCNDOriginalVectorRaster,
            4U);
        CNDLog("[CND_PDF_REACH] TRACE_READY pid=%d hooks=%u/3 "
               "subject=%s query=%s\n", getpid(), hooks,
               CNDCanarySubject, CND_PDF_TRACE_QUERY);
#if CND_PDF_TRACE_SET_QUERY
        dispatch_async(dispatch_get_main_queue(), ^{ CNDTrySetQuery(); });
#endif
    }
    return NULL;
}

__attribute__((constructor))
static void CNDStart(void)
{
    unlink(CNDReportPath);
    gCNDFD = open(CNDReportPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (gCNDFD < 0) return;
    CNDLog("[CND_PDF_REACH] START pid=%d process=%s mode=read-only-"
           "pdf-reachability\n", getpid(), getprogname());
    pthread_t thread = 0;
    int result = pthread_create(&thread, NULL, CNDBootstrap, NULL);
    if (result == 0) {
        (void)pthread_detach(thread);
    } else {
        CNDLog("[CND_PDF_REACH] FAILED reason=thread result=%d\n", result);
    }
}
