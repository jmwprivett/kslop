//
//  Package.m
//  Cyanide
//

#import "Package.h"
#import "PackageQueue.h"
#import "CNDTransientAppliedState.h"
#import "../SettingsViewController.h"
#import "../PatreonAuth.h"
#import "../LogTextView.h"

NSNotificationName const PackageFavoritesDidChangeNotification =
    @"PackageFavoritesDidChangeNotification";

static NSString * const kPackageFavoriteIdentifiersDefault =
    @"installer.favoritePackageIdentifiers.v1";

NSSet<NSString *> *PackageFavoriteIdentifiers(void)
{
    id stored = [[NSUserDefaults standardUserDefaults]
        objectForKey:kPackageFavoriteIdentifiersDefault];
    if (![stored isKindOfClass:[NSArray class]]) return [NSSet set];

    NSMutableSet<NSString *> *identifiers = [NSMutableSet set];
    for (id value in (NSArray *)stored) {
        if ([value isKindOfClass:[NSString class]] && [value length] > 0) {
            [identifiers addObject:value];
        }
    }
    return [identifiers copy];
}

BOOL PackageIdentifierIsFavorite(NSString *identifier)
{
    if (identifier.length == 0) return NO;
    return [PackageFavoriteIdentifiers() containsObject:identifier];
}

void PackageSetIdentifierFavorite(NSString *identifier, BOOL favorite)
{
    if (identifier.length == 0) return;

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableOrderedSet<NSString *> *identifiers = [NSMutableOrderedSet orderedSet];
    id stored = [defaults objectForKey:kPackageFavoriteIdentifiersDefault];
    if ([stored isKindOfClass:[NSArray class]]) {
        for (id value in (NSArray *)stored) {
            if ([value isKindOfClass:[NSString class]] && [value length] > 0) {
                [identifiers addObject:value];
            }
        }
    }

    BOOL wasFavorite = [identifiers containsObject:identifier];
    if (favorite) [identifiers addObject:identifier];
    else [identifiers removeObject:identifier];
    if (wasFavorite == favorite) return;

    [defaults setObject:identifiers.array forKey:kPackageFavoriteIdentifiersDefault];
    [defaults synchronize];

    void (^notify)(void) = ^{
        [[NSNotificationCenter defaultCenter]
            postNotificationName:PackageFavoritesDidChangeNotification
                          object:nil
                        userInfo:@{ @"identifier": identifier,
                                    @"favorite": @(favorite) }];
    };
    if ([NSThread isMainThread]) notify();
    else dispatch_async(dispatch_get_main_queue(), notify);
}

@implementation Package

- (instancetype)initWithIdentifier:(NSString *)identifier
                              name:(NSString *)name
                  shortDescription:(NSString *)shortDescription
                   longDescription:(NSString *)longDescription
                           version:(NSString *)version
                            author:(NSString *)author
                          category:(NSString *)category
                        symbolName:(NSString *)symbolName
                              kind:(PackageInstallKind)kind
                        enabledKey:(NSString *)enabledKey
                             isNew:(BOOL)isNew
{
    if ((self = [super init])) {
        _identifier       = [identifier copy];
        _name             = [name copy];
        _shortDescription = [shortDescription copy];
        _longDescription  = [longDescription copy];
        _version          = [version copy];
        _author           = [author copy];
        _category         = [category copy];
        _symbolName       = [symbolName copy];
        _kind             = kind;
        _enabledKey       = [enabledKey copy];
        _isNew            = isNew;
        _settingsSection  = NSIntegerMax;
    }
    return self;
}

- (BOOL)isInstalled
{
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    switch (self.kind) {
        case PackageInstallKindToggle:
            if (!self.enabledKey) return NO;
            return [d boolForKey:self.enabledKey];
        case PackageInstallKindOTA:
        case PackageInstallKindNanoRegistry:
        case PackageInstallKindCallRecordingSound:
        case PackageInstallKindHideHomeBar:
        case PackageInstallKindFontChanger:
        case PackageInstallKindLockscreenGlyphs:
        case PackageInstallKindControlCenterTheming:
            // Manual-control packages: no persistent "installed" state from
            // the app's POV. The detail view shows an Apply/Restore menu and
            // each commit is a fresh one-shot run.
            return NO;
        case PackageInstallKindDirectTool:
            return NO;
    }
}

- (BOOL)isQueuedForApply
{
    if (self.kind != PackageInstallKindToggle || !self.enabledKey) return NO;
    if (self.isInstallDisabled) return NO;
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    return [d boolForKey:self.enabledKey] && !settings_tweak_is_applied(self.enabledKey);
}

- (BOOL)isInstallDisabled
{
    if (self.installDisabledReason.length > 0) return YES;
    if (self.experimental) {
        BOOL experimentalOn = [[NSUserDefaults standardUserDefaults] boolForKey:kSettingsExperimentalTweaksEnabled];
        if (!experimentalOn || !(cyanide_is_patron() || cyanide_is_creator())) return YES;
    }
    if (self.creatorOnly && !cyanide_is_creator()) return YES;
    return NO;
}

- (BOOL)isAppliedForCurrentSystemEpoch
{
    if ([self.identifier isEqualToString:@"com.darksword.snowboardlite"]) {
        return CNDTransientAppliedStateIsActive(
            CNDTransientAppliedStateSnowBoardRemix);
    }
    if (self.kind == PackageInstallKindFontChanger) {
        return CNDTransientAppliedStateIsActive(
            CNDTransientAppliedStateFontChanger);
    }
    if ([self.identifier isEqualToString:@"com.darksword.sbcustomizer"]) {
        return CNDTransientAppliedStateIsActive(
            CNDTransientAppliedStateSBCustomizer);
    }
    return NO;
}

- (void)install   { [[PackageQueue sharedQueue] toggleForPackage:self]; }
- (void)uninstall { [[PackageQueue sharedQueue] toggleForPackage:self]; }

// Called by PackageQueue.commit — writes the persisted state without
// triggering settings_run_actions itself (the queue does that once).
- (BOOL)applyCommittedState:(BOOL)installed
{
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    switch (self.kind) {
        case PackageInstallKindToggle:
            if (!self.enabledKey) return NO;
            [d setBool:installed forKey:self.enabledKey];
            return [d synchronize];
        case PackageInstallKindOTA:
        {
            BOOL success = settings_apply_ota_disabled(installed);
            if (success) {
                log_user("[INSTALLER] OTA updates %s.\n", installed ? "disabled" : "enabled");
            } else {
                log_user("[INSTALLER] OTA %s failed; install state was not changed.\n",
                         installed ? "disable" : "enable");
            }
            return success;
        }
        case PackageInstallKindNanoRegistry:
        {
            BOOL success = settings_apply_nano_registry_now(installed);
            if (success) {
                log_user("[INSTALLER] Watch pairing override %s.\n",
                         installed ? "applied" : "removed");
            } else {
                log_user("[INSTALLER] Watch pairing override %s failed; state was not changed.\n",
                         installed ? "apply" : "remove");
            }
            return success;
        }
        case PackageInstallKindCallRecordingSound:
        {
            BOOL success = settings_apply_call_recording_sound_disabled(installed);
            if (success) {
                log_user("[INSTALLER] Call recording disclosure sound %s.\n",
                         installed ? "silenced" : "restored");
            } else {
                log_user("[INSTALLER] Call recording disclosure sound %s failed.\n",
                         installed ? "silence" : "restore");
            }
            return success;
        }
        case PackageInstallKindHideHomeBar:
        {
            BOOL success = settings_apply_hide_home_bar_hidden(installed);
            if (success) {
                log_user("[INSTALLER] Home bar %s.\n",
                         installed ? "hidden; respring to apply" : "restore queued; respring to apply");
            } else {
                log_user("[INSTALLER] Home bar %s failed.\n",
                         installed ? "hide" : "restore");
            }
            return success;
        }
        case PackageInstallKindFontChanger:
        {
            BOOL success = settings_apply_font_changer_now(installed);
            if (success) {
                log_user("[INSTALLER] Font Changer %s; respring to apply.\n",
                         installed ? "applied" : "restored");
            } else {
                log_user("[INSTALLER] Font Changer %s failed.\n",
                         installed ? "apply" : "restore");
            }
            return success;
        }
        case PackageInstallKindControlCenterTheming:
        {
            BOOL success = settings_apply_cc_theming_now(installed);
            if (success) {
                log_user("[INSTALLER] Control Center resources %s; respring queued.\n",
                         installed ? "applied" : "restored");
            } else {
                log_user("[INSTALLER] Control Center resource %s failed.\n",
                         installed ? "apply" : "restore");
            }
            return success;
        }
        case PackageInstallKindLockscreenGlyphs:
        case PackageInstallKindDirectTool:
            return NO;
    }
}

@end
