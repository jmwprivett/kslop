#ifndef CNDKernelTaskBridge_h
#define CNDKernelTaskBridge_h

#import <Foundation/Foundation.h>
#import <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

/// A short-lived, PID-bound task-memory channel. The vPhone lab delegates to
/// its root task-port provider. The legacy non-PAC route can temporarily
/// rebind a local Mach port with KRW, but physical arm64e fails closed before
/// touching ip_kobject because that field requires destination-specific
/// kernel pointer authentication.
@interface CNDKernelTaskBridgeSession : NSObject

@property(nonatomic, readonly) pid_t pid;
@property(nonatomic, copy, readonly) NSString *processName;
@property(nonatomic, copy, readonly) NSString *mode;
@property(nonatomic, readonly, getter=isOpen) BOOL open;

+ (nullable instancetype)openProcess:(NSString *)processName
                               error:(NSError * _Nullable * _Nullable)error;
+ (nullable instancetype)openPID:(pid_t)pid
             expectedProcessName:(NSString *)processName
                           error:(NSError * _Nullable * _Nullable)error;

- (kern_return_t)allocateLength:(size_t)length
                     addressOut:(uint64_t *)addressOut;
- (kern_return_t)readAddress:(uint64_t)address
                      buffer:(void *)buffer
                      length:(size_t)length;
- (kern_return_t)writeAddress:(uint64_t)address
                       buffer:(const void *)buffer
                       length:(size_t)length;
- (kern_return_t)deallocateAddress:(uint64_t)address length:(size_t)length;
- (kern_return_t)protectRXAddress:(uint64_t)address length:(size_t)length;
- (kern_return_t)flushInstructionCacheAtAddress:(uint64_t)address
                                          length:(size_t)length;
- (kern_return_t)startBootstrapThreadAtAddress:(uint64_t)entryPoint
                                  stackPointer:(uint64_t)stackPointer;
- (kern_return_t)terminateBootstrapThread;
- (BOOL)identityIsStable;
- (BOOL)close;

@end

/// Resolves one exact live process incarnation without opening a task-control
/// channel. The lifecycle watcher uses this inexpensive identity probe to
/// notice PID replacement before invoking the PID-bound installer once.
pid_t CNDKernelTaskBridgeResolveProcessPID(
    NSString *processName,
    NSError * _Nullable * _Nullable error);

/// Phase-1 direct-task proof. It is supported by the vPhone root lab and the
/// legacy non-PAC bridge, and reports an explicit unsupported result on
/// physical arm64e. It never executes target code.
NSDictionary<NSString *, id> *
CNDKernelTaskBridgeProbeProcess(NSString *processName);

/// PID-bound variant used by lifecycle watchers, which already receive the
/// process identifier from the launch event and must not perform a name scan.
NSDictionary<NSString *, id> *
CNDKernelTaskBridgeProbePID(pid_t pid, NSString *expectedProcessName);

NS_ASSUME_NONNULL_END

#endif /* CNDKernelTaskBridge_h */
