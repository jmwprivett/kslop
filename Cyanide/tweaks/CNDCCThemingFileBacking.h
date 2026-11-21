#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Installs only proven iOS 26 package/catalog resource routes. Native providers
/// read the modified files on their next resource load. No SpringBoard objects,
/// classes, executable payloads, control actions, or radio settings are changed.
NSDictionary<NSString *, id> *CNDCCThemingFileBackingApply(void);
NSDictionary<NSString *, id> *CNDCCThemingFileBackingRestore(void);
BOOL CNDCCThemingFileBackingHasJournaledState(void);

/// Live evidence for the applied theme, taken from the target bytes rather than
/// from the journal alone: a respring or reboot can revert the system resources
/// while the journal still records them as applied. Unknown is the zero value;
/// the probe resolves to Stock, Applied or Partial.
typedef NS_ENUM(NSInteger, CNDCCThemingFileBackingLiveState) {
    CNDCCThemingFileBackingLiveStateUnknown = 0,
    CNDCCThemingFileBackingLiveStateStock,
    CNDCCThemingFileBackingLiveStateApplied,
    CNDCCThemingFileBackingLiveStatePartial,
};
/// Read-only and bounded; safe to call from UI state queries.
CNDCCThemingFileBackingLiveState CNDCCThemingFileBackingLiveStateNow(void);

#if defined(CND_CC_FILE_BACKING_TESTING)
typedef BOOL (^CNDCCFileBackingTestWriter)(NSString *target, NSString *source);
CNDCCThemingFileBackingLiveState CNDCCThemingFileBackingLiveStateInDirectory(
    NSURL *journalDirectory, NSURL *targetRoot);
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
