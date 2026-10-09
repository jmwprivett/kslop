#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Installs only proven iOS 26 package/catalog resource routes. Native providers
/// read the modified files on their next resource load. No SpringBoard objects,
/// classes, executable payloads, control actions, or radio settings are changed.
NSDictionary<NSString *, id> *CNDCCThemingFileBackingApply(void);
NSDictionary<NSString *, id> *CNDCCThemingFileBackingRestore(void);
BOOL CNDCCThemingFileBackingHasJournaledState(void);

#if defined(CND_CC_FILE_BACKING_TESTING)
typedef BOOL (^CNDCCFileBackingTestWriter)(NSString *target, NSString *source);
NSDictionary *CNDCCThemingFileBackingRunFixture(
    BOOL apply, NSDictionary * _Nullable manifest, NSURL *artworkDirectory,
    NSURL *targetRoot, NSURL *journalDirectory, NSString *productBuildVersion,
    CNDCCFileBackingTestWriter writer);
NSData * _Nullable CNDCCThemingFileBackingPrepareFixture(
    NSData *nativeMain, NSData *sourceMain, NSString *kind, NSURL *imageDirectory,
    NSError **error);
NSData * _Nullable CNDCCThemingFileBackingPrepareGeometryFixture(
    NSData *nativeMain, NSData *sourceMain, NSString *kind, NSURL *imageDirectory,
    NSDictionary *geometry, NSError **error);
#endif

NS_ASSUME_NONNULL_END
