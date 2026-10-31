//
//  DSKeepAlive.m
//  Cyanide
//

#import "DSKeepAlive.h"
#import "LogTextView.h"
#import <AVFoundation/AVFoundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>

static AVAudioPlayer *gKeepAlivePlayer;
static BOOL gKeepAliveRunning = NO;
static BOOL gKeepAliveObserversInstalled = NO;
static BOOL gKeepAliveInterrupted = NO;
static uint64_t gKeepAliveRecoveryGeneration = 0;

static NSObject *ds_keepalive_lock(void)
{
    static NSObject *lock = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        lock = [NSObject new];
    });
    return lock;
}

static dispatch_queue_t ds_keepalive_recovery_queue(void)
{
    static dispatch_queue_t queue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        queue = dispatch_queue_create("com.zeroxjf.cyanide.keepalive.recovery",
                                      DISPATCH_QUEUE_SERIAL);
    });
    return queue;
}

static void ds_append_u16(NSMutableData *data, uint16_t value)
{
    uint16_t le = CFSwapInt16HostToLittle(value);
    [data appendBytes:&le length:sizeof(le)];
}

static void ds_append_u32(NSMutableData *data, uint32_t value)
{
    uint32_t le = CFSwapInt32HostToLittle(value);
    [data appendBytes:&le length:sizeof(le)];
}

static NSURL *ds_keepalive_wav_url(void)
{
    NSArray<NSURL *> *caches = [[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory
                                                                      inDomains:NSUserDomainMask];
    NSURL *dir = caches.firstObject ?: [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
    return [dir URLByAppendingPathComponent:@"ds_keepalive_silence.wav"];
}

static BOOL ds_keepalive_ensure_wav(NSURL *url)
{
    if ([[NSFileManager defaultManager] fileExistsAtPath:url.path]) return YES;

    const uint32_t sampleRate = 44100;
    const uint16_t channels = 1;
    const uint16_t bitsPerSample = 16;
    const uint16_t blockAlign = channels * (bitsPerSample / 8);
    const uint32_t durationSeconds = 1;
    const uint32_t dataSize = sampleRate * durationSeconds * blockAlign;
    const uint32_t byteRate = sampleRate * blockAlign;

    NSMutableData *wav = [NSMutableData dataWithCapacity:44 + dataSize];
    [wav appendBytes:"RIFF" length:4];
    ds_append_u32(wav, 36 + dataSize);
    [wav appendBytes:"WAVE" length:4];
    [wav appendBytes:"fmt " length:4];
    ds_append_u32(wav, 16);
    ds_append_u16(wav, 1);
    ds_append_u16(wav, channels);
    ds_append_u32(wav, sampleRate);
    ds_append_u32(wav, byteRate);
    ds_append_u16(wav, blockAlign);
    ds_append_u16(wav, bitsPerSample);
    [wav appendBytes:"data" length:4];
    ds_append_u32(wav, dataSize);
    [wav appendData:[NSMutableData dataWithLength:dataSize]];

    NSError *error = nil;
    if (![wav writeToURL:url options:NSDataWritingAtomic error:&error]) {
        log_user("[WARN] Keep Alive could not create its silent audio file: %s\n",
                 error.localizedDescription.UTF8String);
        return NO;
    }
    return YES;
}

// Arm the AVAudioSession + player. Assumes the global lock is held.
static BOOL ds_keepalive_arm_locked(void)
{
    NSError *error = nil;
    AVAudioSession *session = [AVAudioSession sharedInstance];
    if (![session setCategory:AVAudioSessionCategoryPlayback
                  withOptions:AVAudioSessionCategoryOptionMixWithOthers
                        error:&error]) {
        log_user("[WARN] Keep Alive audio session failed: %s\n", error.localizedDescription.UTF8String);
        return NO;
    }
    // This is a preference, not an assertion: accepted calls and other
    // nonmixable owners can still interrupt us. It does avoid losing the
    // silent stream to system-alert audio in the cases iOS supports.
    error = nil;
    if (![session setPrefersNoInterruptionsFromSystemAlerts:YES error:&error]) {
        log_user("[WARN] Keep Alive could not suppress system-alert interruptions: %s\n",
                 error.localizedDescription.UTF8String);
    }
    error = nil;
    if (![session setActive:YES error:&error]) {
        log_user("[WARN] Keep Alive could not activate audio: %s\n", error.localizedDescription.UTF8String);
        return NO;
    }

    if (!gKeepAlivePlayer) {
        NSURL *url = ds_keepalive_wav_url();
        if (!ds_keepalive_ensure_wav(url)) return NO;

        AVAudioPlayer *player = [[AVAudioPlayer alloc] initWithContentsOfURL:url error:&error];
        if (!player) {
            log_user("[WARN] Keep Alive audio player failed: %s\n", error.localizedDescription.UTF8String);
            return NO;
        }
        player.numberOfLoops = -1;
        player.volume = 0.0f;
        [player prepareToPlay];
        gKeepAlivePlayer = player;
    }

    if (!gKeepAlivePlayer.isPlaying && ![gKeepAlivePlayer play]) {
        log_user("[WARN] Keep Alive audio player refused to start.\n");
        return NO;
    }
    return YES;
}

static BOOL ds_keepalive_revive(NSString *reason, BOOL forceReactivation)
{
    @synchronized (ds_keepalive_lock()) {
        if (!gKeepAliveRunning) return NO;
        if (!forceReactivation && gKeepAlivePlayer &&
            gKeepAlivePlayer.isPlaying) return YES;
        if (ds_keepalive_arm_locked()) {
            gKeepAliveInterrupted = NO;
            log_user("[APP] Keep Alive revived (%s).\n", reason.UTF8String);
            return YES;
        } else {
            log_user("[WARN] Keep Alive revive failed (%s); StatBar updates may pause until app foreground.\n",
                     reason.UTF8String);
            return NO;
        }
    }
}

static BOOL ds_keepalive_rebuild(NSString *reason)
{
    @synchronized (ds_keepalive_lock()) {
        if (!gKeepAliveRunning) return NO;
        // mediaservicesd restarted — every audio object we hold is invalid.
        [gKeepAlivePlayer stop];
        gKeepAlivePlayer = nil;
        if (ds_keepalive_arm_locked()) {
            gKeepAliveInterrupted = NO;
            log_user("[APP] Keep Alive rebuilt after %s.\n", reason.UTF8String);
            return YES;
        } else {
            log_user("[WARN] Keep Alive rebuild failed after %s.\n", reason.UTF8String);
            return NO;
        }
    }
}

static void ds_keepalive_recovery_attempt(uint64_t generation,
                                          NSUInteger attempt,
                                          NSString *reason,
                                          BOOL rebuild)
{
    static const int64_t delaysNS[] = {
        0,
        250LL * NSEC_PER_MSEC,
        1LL * NSEC_PER_SEC,
        5LL * NSEC_PER_SEC,
    };
    const NSUInteger count = sizeof(delaysNS) / sizeof(delaysNS[0]);
    if (attempt >= count) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, delaysNS[attempt]),
                   ds_keepalive_recovery_queue(), ^{
        @synchronized (ds_keepalive_lock()) {
            if (!gKeepAliveRunning ||
                generation != gKeepAliveRecoveryGeneration) return;
        }

        BOOL recovered = rebuild && attempt == 0
            ? ds_keepalive_rebuild(reason)
            : ds_keepalive_revive(reason, YES);
        if (recovered) return;

        if (attempt + 1 < count) {
            ds_keepalive_recovery_attempt(
                generation, attempt + 1, reason, NO);
        } else {
            log_user("[WARN] Keep Alive exhausted bounded recovery attempts (%s).\n",
                     reason.UTF8String);
        }
    });
}

static void ds_keepalive_schedule_recovery(NSString *reason, BOOL rebuild)
{
    uint64_t generation = 0;
    @synchronized (ds_keepalive_lock()) {
        if (!gKeepAliveRunning) return;
        generation = ++gKeepAliveRecoveryGeneration;
    }
    ds_keepalive_recovery_attempt(
        generation, 0, [reason copy] ?: @"audio event", rebuild);
}

static void ds_keepalive_install_observers_once(void)
{
    if (gKeepAliveObserversInstalled) return;
    gKeepAliveObserversInstalled = YES;

    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

    [nc addObserverForName:AVAudioSessionInterruptionNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *note) {
        NSNumber *typeNum = note.userInfo[AVAudioSessionInterruptionTypeKey];
        AVAudioSessionInterruptionType type =
            (AVAudioSessionInterruptionType)typeNum.unsignedIntegerValue;
        if (type == AVAudioSessionInterruptionTypeBegan) {
            BOOL wasRunning = NO;
            @synchronized (ds_keepalive_lock()) {
                if (gKeepAliveRunning) {
                    wasRunning = YES;
                    gKeepAliveInterrupted = YES;
                    ++gKeepAliveRecoveryGeneration;
                }
            }
            if (wasRunning) {
                log_user("[APP] Keep Alive audio interruption began.\n");
            }
        } else if (type == AVAudioSessionInterruptionTypeEnded) {
            // iOS posts this when the interrupting audio finishes (call hung up,
            // Siri dismissed, alarm dismissed). Reactivate even if the OS didn't
            // set AVAudioSessionInterruptionOptionShouldResume — silent keepalive
            // doesn't get that hint reliably on iOS 18.
            BOOL shouldRecover = NO;
            @synchronized (ds_keepalive_lock()) {
                shouldRecover = gKeepAliveRunning && gKeepAliveInterrupted;
            }
            if (shouldRecover) {
                ds_keepalive_schedule_recovery(@"interruption ended", NO);
            }
        }
    }];

    [nc addObserverForName:AVAudioSessionMediaServicesWereResetNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *note) {
        (void)note;
        ds_keepalive_schedule_recovery(@"mediaservices reset", YES);
    }];

    [nc addObserverForName:AVAudioSessionRouteChangeNotification
                    object:nil
                     queue:nil
                usingBlock:^(NSNotification *note) {
        NSNumber *reasonNum = note.userInfo[AVAudioSessionRouteChangeReasonKey];
        AVAudioSessionRouteChangeReason reason =
            (AVAudioSessionRouteChangeReason)reasonNum.unsignedIntegerValue;
        if (reason == AVAudioSessionRouteChangeReasonOldDeviceUnavailable ||
            reason == AVAudioSessionRouteChangeReasonNewDeviceAvailable ||
            reason == AVAudioSessionRouteChangeReasonOverride) {
            // iOS's default is to pause on OldDeviceUnavailable (headphones
            // unplugged, AirPods out of ear). We don't want that for the
            // silent assertion.
            ds_keepalive_schedule_recovery(@"route change", NO);
        }
    }];

    [nc addObserverForName:UIApplicationDidBecomeActiveNotification
                    object:nil
                     queue:[NSOperationQueue mainQueue]
                usingBlock:^(NSNotification *note) {
        (void)note;
        ds_keepalive_schedule_recovery(@"app became active", NO);
    }];
}

void ds_keepalive_apply_enabled(BOOL enabled)
{
    BOOL scheduleRecovery = NO;
    @synchronized (ds_keepalive_lock()) {
        if (!enabled) {
            if (gKeepAlivePlayer || gKeepAliveRunning) {
                ++gKeepAliveRecoveryGeneration;
                [gKeepAlivePlayer stop];
                gKeepAlivePlayer = nil;
                gKeepAliveRunning = NO;
                gKeepAliveInterrupted = NO;
                [[AVAudioSession sharedInstance] setActive:NO
                                                withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation
                                                      error:nil];
                log_user("[APP] Keep Alive disabled; app-side tweak feeds can pause when minimized.\n");
            }
            return;
        }

        if (gKeepAliveRunning && gKeepAlivePlayer.isPlaying) return;
        gKeepAliveRunning = YES;
        ds_keepalive_install_observers_once();
        if (!ds_keepalive_arm_locked()) {
            scheduleRecovery = YES;
        }
    }
    if (scheduleRecovery) {
        ds_keepalive_schedule_recovery(@"enable", NO);
    }
}

BOOL ds_keepalive_is_running(void)
{
    @synchronized (ds_keepalive_lock()) {
        return gKeepAliveRunning && gKeepAlivePlayer.isPlaying;
    }
}
