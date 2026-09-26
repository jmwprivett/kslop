//
//  font_changer.m
//  Cyanide
//

#import "font_changer.h"
#import "../LogTextView.h"
#import "../utils/file.h"

#import <Foundation/Foundation.h>
#import <errno.h>
#import <sys/stat.h>
#import <unistd.h>

NSString * const CNDFontChangerRoleRegular = @"regular";
NSString * const CNDFontChangerRoleItalic  = @"italic";
NSString * const CNDFontChangerRoleMono    = @"mono";

static NSString * const kFCFontsDirName = @"Fonts";
static NSString * const kFCSelectedDirName = @"Selected";
static NSString * const kFCStockExportDirName = @"StockExport";
static NSString * const kFCBackupDirName = @"FontBackups";
static NSString * const kFCAppBackupDirName = @"AppFontBackups";
static NSString * const kFCFamilyNameKey = @"FontChangerFamilyName";
static NSString * const kFCRegularPathKey = @"FontChangerRegularPath";
static NSString * const kFCItalicPathKey = @"FontChangerItalicPath";
static NSString * const kFCMonoPathKey = @"FontChangerMonoPath";
static NSString * const kFCAppTargetBundleIDKey = @"FontChangerAppTargetBundleID";
static NSString * const kFCAppTargetNameKey = @"FontChangerAppTargetName";
static NSString * const kFCAppTargetBundlePathKey = @"FontChangerAppTargetBundlePath";
static NSString * const kFCAppOverridesKey = @"FontChangerAppOverrides";

typedef struct {
    __unsafe_unretained NSString *role;
    __unsafe_unretained NSString *displayName;
    __unsafe_unretained NSString *targetPath;
    __unsafe_unretained NSString *fileStem;
    __unsafe_unretained NSString *defaultsKey;
} CNDFontRoleInfo;

static const CNDFontRoleInfo kFCRoles[] = {
    { CNDFontChangerRoleRegular, @"Regular", @"/System/Library/Fonts/Core/SFUI.ttf",       @"Regular", kFCRegularPathKey },
    { CNDFontChangerRoleItalic,  @"Italic",  @"/System/Library/Fonts/Core/SFUIItalic.ttf", @"Italic",  kFCItalicPathKey },
    { CNDFontChangerRoleMono,    @"Mono",    @"/System/Library/Fonts/Core/SFUIMono.ttf",   @"Mono",    kFCMonoPathKey },
};

static NSUInteger fc_role_count(void)
{
    return sizeof(kFCRoles) / sizeof(kFCRoles[0]);
}

static const CNDFontRoleInfo *fc_info_for_role(NSString *role)
{
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        if ([kFCRoles[i].role isEqualToString:role]) return &kFCRoles[i];
    }
    return NULL;
}

NSArray<NSString *> *font_changer_all_roles(void)
{
    return @[ CNDFontChangerRoleRegular, CNDFontChangerRoleItalic, CNDFontChangerRoleMono ];
}

NSString *font_changer_role_display_name(NSString *role)
{
    const CNDFontRoleInfo *info = fc_info_for_role(role);
    return info ? info->displayName : @"Font";
}

NSString *font_changer_role_target_path(NSString *role)
{
    const CNDFontRoleInfo *info = fc_info_for_role(role);
    return info ? info->targetPath : @"";
}

BOOL font_changer_target_exists(NSString *role)
{
    NSString *path = font_changer_role_target_path(role);
    return path.length > 0 && [[NSFileManager defaultManager] fileExistsAtPath:path];
}

static NSString *fc_documents_dir(void)
{
    NSArray<NSString *> *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                                    NSUserDomainMask,
                                                                    YES);
    return dirs.firstObject ?: NSHomeDirectory();
}

static NSString *fc_selected_dir(void)
{
    return [[fc_documents_dir() stringByAppendingPathComponent:kFCFontsDirName]
            stringByAppendingPathComponent:kFCSelectedDirName];
}

static NSString *fc_stock_export_dir(void)
{
    return [[fc_documents_dir() stringByAppendingPathComponent:kFCFontsDirName]
            stringByAppendingPathComponent:kFCStockExportDirName];
}

static NSString *fc_backup_dir(void)
{
    return [fc_documents_dir() stringByAppendingPathComponent:kFCBackupDirName];
}

static NSString *fc_app_backup_dir(void)
{
    return [fc_documents_dir() stringByAppendingPathComponent:kFCAppBackupDirName];
}

static NSString *fc_relative_path_for_absolute(NSString *path)
{
    NSString *docs = fc_documents_dir();
    if (path.length == 0 || docs.length == 0) return @"";
    NSString *prefix = [docs stringByAppendingString:@"/"];
    if ([path hasPrefix:prefix]) return [path substringFromIndex:prefix.length];
    return path;
}

static NSString *fc_absolute_path_for_relative(NSString *path)
{
    if (path.length == 0) return @"";
    if ([path hasPrefix:@"/"]) return path;
    return [fc_documents_dir() stringByAppendingPathComponent:path];
}

static NSString *fc_selected_path_for_role(NSString *role)
{
    const CNDFontRoleInfo *info = fc_info_for_role(role);
    if (!info) return @"";
    NSString *relative = [NSUserDefaults.standardUserDefaults stringForKey:info->defaultsKey] ?: @"";
    return fc_absolute_path_for_relative(relative);
}

static BOOL fc_file_exists_nonempty(NSString *path)
{
    if (path.length == 0) return NO;
    NSDictionary<NSFileAttributeKey, id> *attrs =
        [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    return [attrs[NSFileSize] unsignedLongLongValue] > 0;
}

static BOOL fc_stat_path(NSString *path, off_t *sizeOut);
static void fc_log_font_file_diagnostics(NSString *label, NSString *path);

static NSString *fc_backup_path_for_role(NSString *role)
{
    const CNDFontRoleInfo *info = fc_info_for_role(role);
    if (!info) return @"";
    return [fc_backup_dir() stringByAppendingPathComponent:
            [info->targetPath.lastPathComponent stringByAppendingString:@".orig"]];
}

static BOOL fc_extension_allowed(NSString *extension)
{
    NSString *ext = extension.lowercaseString ?: @"";
    return [(@[@"ttf", @"otf", @"ttc"]) containsObject:ext];
}

static BOOL fc_set_error(NSError **error, NSInteger code, NSString *message)
{
    if (error) {
        *error = [NSError errorWithDomain:@"CyanideFontChanger"
                                     code:code
                                 userInfo:@{ NSLocalizedDescriptionKey: message ?: @"Font import failed." }];
    }
    return NO;
}

BOOL font_changer_import_font(NSURL *url, NSString *role, NSError **error)
{
    const CNDFontRoleInfo *info = fc_info_for_role(role);
    if (!info) return fc_set_error(error, 1, @"Unknown font role.");
    if (!url.path.length) return fc_set_error(error, 2, @"The selected font could not be opened.");

    BOOL isDir = NO;
    NSFileManager *fm = NSFileManager.defaultManager;
    if (![fm fileExistsAtPath:url.path isDirectory:&isDir] || isDir) {
        return fc_set_error(error, 3, @"Choose a TTF, OTF, or TTC font file.");
    }
    if (!fc_extension_allowed(url.pathExtension)) {
        return fc_set_error(error, 4, @"Choose a TTF, OTF, or TTC font file.");
    }
    if (!fc_file_exists_nonempty(url.path)) {
        return fc_set_error(error, 5, @"The selected font is empty or unreadable.");
    }

    NSString *dir = fc_selected_dir();
    if (![fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:error]) {
        return NO;
    }

    for (NSString *ext in @[@"ttf", @"otf", @"ttc"]) {
        NSString *old = [dir stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"%@.%@", info->fileStem, ext]];
        [fm removeItemAtPath:old error:nil];
    }

    NSString *ext = url.pathExtension.lowercaseString;
    NSString *dest = [dir stringByAppendingPathComponent:
                      [NSString stringWithFormat:@"%@.%@", info->fileStem, ext]];
    [fm removeItemAtPath:dest error:nil];
    if (![fm copyItemAtURL:url toURL:[NSURL fileURLWithPath:dest] error:error]) {
        return NO;
    }

    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    [d setObject:fc_relative_path_for_absolute(dest) forKey:info->defaultsKey];
    if ([role isEqualToString:CNDFontChangerRoleRegular]) {
        NSString *base = url.URLByDeletingPathExtension.lastPathComponent;
        [d setObject:(base.length ? base : @"Custom Font") forKey:kFCFamilyNameKey];
    } else if (![[d stringForKey:kFCFamilyNameKey] length]) {
        [d setObject:@"Custom Font" forKey:kFCFamilyNameKey];
    }
    [d synchronize];

    log_user("[FONT] Imported %s font: %s (%llu bytes).\n",
             info->displayName.UTF8String,
             url.lastPathComponent.UTF8String,
             (unsigned long long)[[fm attributesOfItemAtPath:dest error:nil][NSFileSize] unsignedLongLongValue]);
    return YES;
}

void font_changer_clear_selected_family(void)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    [fm removeItemAtPath:fc_selected_dir() error:nil];
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    [d removeObjectForKey:kFCFamilyNameKey];
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        [d removeObjectForKey:kFCRoles[i].defaultsKey];
    }
    [d synchronize];
    log_user("[FONT] Cleared selected font family.\n");
}

BOOL font_changer_has_regular_font(void)
{
    return fc_file_exists_nonempty(fc_selected_path_for_role(CNDFontChangerRoleRegular));
}

BOOL font_changer_has_any_selected_font(void)
{
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        if (fc_file_exists_nonempty(fc_selected_path_for_role(kFCRoles[i].role))) return YES;
    }
    return NO;
}

NSString *font_changer_selected_family_summary(void)
{
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    NSString *name = [d stringForKey:kFCFamilyNameKey] ?: @"";
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        if (fc_file_exists_nonempty(fc_selected_path_for_role(kFCRoles[i].role))) {
            [parts addObject:kFCRoles[i].displayName];
        }
    }
    if (parts.count == 0) return @"No font family selected.";
    NSString *label = name.length ? name : @"Custom Font";
    return [NSString stringWithFormat:@"%@ (%@)", label, [parts componentsJoinedByString:@", "]];
}

NSString *font_changer_role_summary(NSString *role)
{
    NSString *path = fc_selected_path_for_role(role);
    if (!fc_file_exists_nonempty(path)) return @"Not imported.";
    NSDictionary<NSFileAttributeKey, id> *attrs =
        [NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
    unsigned long long bytes = [attrs[NSFileSize] unsignedLongLongValue];
    return [NSString stringWithFormat:@"%@ (%llu bytes)", path.lastPathComponent, bytes];
}

NSArray<NSURL *> *font_changer_export_current_system_fonts(NSError **error)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *dir = fc_stock_export_dir();
    [fm removeItemAtPath:dir error:nil];
    if (![fm createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:error]) {
        log_user("[FONT] Export failed: could not create %s\n", dir.UTF8String);
        return nil;
    }

    NSMutableArray<NSURL *> *urls = [NSMutableArray array];
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        NSString *source = kFCRoles[i].targetPath;
        off_t size = 0;
        if (!fc_stat_path(source, &size)) {
            log_user("[FONT] Export skipped %s: target missing or unreadable at %s\n",
                     kFCRoles[i].displayName.UTF8String,
                     source.UTF8String);
            continue;
        }

        NSString *dest = [dir stringByAppendingPathComponent:source.lastPathComponent];
        NSError *copyError = nil;
        if (![fm copyItemAtPath:source toPath:dest error:&copyError]) {
            log_user("[FONT] Export failed for %s: %s\n",
                     kFCRoles[i].displayName.UTF8String,
                     copyError.localizedDescription.UTF8String ?: "unknown");
            if (error) *error = copyError;
            return nil;
        }
        chmod(dest.UTF8String, 0600);
        [urls addObject:[NSURL fileURLWithPath:dest]];
        log_user("[FONT] Exported current %s font: %s (%lld bytes).\n",
                 kFCRoles[i].displayName.UTF8String,
                 dest.UTF8String,
                 (long long)size);
    }

    if (urls.count == 0) {
        fc_set_error(error, 20, @"No system font targets were readable for export.");
        return nil;
    }

    log_user("[OK] Exported current system fonts to %s\n", dir.UTF8String);
    return urls;
}

static BOOL fc_stat_path(NSString *path, off_t *sizeOut)
{
    struct stat st = {0};
    if (stat(path.UTF8String, &st) != 0) return NO;
    if (sizeOut) *sizeOut = st.st_size;
    return st.st_size > 0 && S_ISREG(st.st_mode);
}

static BOOL fc_preflight_pair(NSString *role, NSString *source, NSString *target)
{
    off_t sourceSize = 0;
    off_t targetSize = 0;
    NSString *display = font_changer_role_display_name(role);

    if (!fc_stat_path(source, &sourceSize)) {
        log_user("[FONT] %s font is missing or unreadable: %s\n",
                 display.UTF8String, source.UTF8String);
        return NO;
    }
    if (!fc_stat_path(target, &targetSize)) {
        log_user("[FONT] Target for %s does not exist on this device: %s\n",
                 display.UTF8String, target.UTF8String);
        return NO;
    }
    if (sourceSize > targetSize) {
        log_user("[FONT] %s font is too large: replacement=%lld target=%lld. Choose a smaller font.\n",
                 display.UTF8String, (long long)sourceSize, (long long)targetSize);
        return NO;
    }
    return YES;
}

static BOOL fc_ensure_backup_for_role(NSString *role)
{
    NSString *target = font_changer_role_target_path(role);
    NSString *backup = fc_backup_path_for_role(role);
    NSString *display = font_changer_role_display_name(role);
    NSFileManager *fm = NSFileManager.defaultManager;

    if ([fm fileExistsAtPath:backup]) return YES;
    if (![fm createDirectoryAtPath:fc_backup_dir()
       withIntermediateDirectories:YES
                        attributes:nil
                             error:nil]) {
        log_user("[FONT] Could not create backup folder.\n");
        return NO;
    }

    NSError *error = nil;
    if (![fm copyItemAtPath:target toPath:backup error:&error]) {
        log_user("[FONT] Could not back up %s font: %s\n",
                 display.UTF8String,
                 error.localizedDescription.UTF8String ?: "unknown");
        return NO;
    }
    chmod(backup.UTF8String, 0600);

    off_t size = 0;
    fc_stat_path(backup, &size);
    log_user("[FONT] Backed up stock %s font (%lld bytes).\n",
             display.UTF8String, (long long)size);
    return YES;
}

static BOOL fc_overwrite(NSString *target, NSString *source, NSString *label)
{
    uint64_t rc = overwrite_system_file((char *)target.UTF8String, (char *)source.UTF8String);
    if (rc != 0) {
        log_user("[FONT] %s overwrite failed: target=%s source=%s\n",
                 label.UTF8String, target.UTF8String, source.UTF8String);
        return NO;
    }
    return YES;
}

bool font_changer_apply_selected_family(void)
{
    if (!font_changer_has_regular_font()) {
        log_user("[FONT] Import a Regular font before applying a family.\n");
        return false;
    }

    NSMutableArray<NSString *> *roles = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSString *> *sources = [NSMutableDictionary dictionary];
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        NSString *source = fc_selected_path_for_role(kFCRoles[i].role);
        if (fc_file_exists_nonempty(source)) {
            [roles addObject:kFCRoles[i].role];
            sources[kFCRoles[i].role] = source;
        }
    }

    for (NSString *role in roles) {
        if (!fc_preflight_pair(role, sources[role], font_changer_role_target_path(role))) {
            log_user("[FAIL] Font Changer preflight failed. No fonts were overwritten.\n");
            return false;
        }
    }
    for (NSString *role in roles) {
        if (!fc_ensure_backup_for_role(role)) {
            log_user("[FAIL] Font Changer backup failed. No fonts were overwritten.\n");
            return false;
        }
    }

    BOOL ok = YES;
    for (NSString *role in roles) {
        NSString *label = font_changer_role_display_name(role);
        NSString *target = font_changer_role_target_path(role);
        NSString *source = sources[role];
        log_user("[FONT] Applying %s font: %s -> %s\n",
                 label.UTF8String, source.lastPathComponent.UTF8String, target.UTF8String);
        ok = fc_overwrite(target, source, label) && ok;
    }

    if (ok) {
        log_user("[OK] Font family applied. Respring to refresh system font caches.\n");
    } else {
        log_user("[FAIL] Font family apply was incomplete. Restore stock fonts if anything looks wrong.\n");
    }
    return ok;
}

bool font_changer_restore_originals(void)
{
    NSMutableArray<NSString *> *roles = [NSMutableArray array];
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        NSString *backup = fc_backup_path_for_role(kFCRoles[i].role);
        if (fc_file_exists_nonempty(backup)) {
            [roles addObject:kFCRoles[i].role];
        }
    }
    if (roles.count == 0) {
        log_user("[FONT] No stock font backups were found in kslop Documents.\n");
        return false;
    }

    for (NSString *role in roles) {
        if (!fc_preflight_pair(role, fc_backup_path_for_role(role), font_changer_role_target_path(role))) {
            log_user("[FAIL] Font restore preflight failed. No fonts were restored.\n");
            return false;
        }
    }

    BOOL ok = YES;
    for (NSString *role in roles) {
        NSString *label = font_changer_role_display_name(role);
        NSString *target = font_changer_role_target_path(role);
        NSString *backup = fc_backup_path_for_role(role);
        log_user("[FONT] Restoring stock %s font.\n", label.UTF8String);
        ok = fc_overwrite(target, backup, label) && ok;
    }

    if (ok) {
        log_user("[OK] Stock font backups restored. Respring to refresh system font caches.\n");
    } else {
        log_user("[FAIL] Font restore was incomplete.\n");
    }
    return ok;
}

static unsigned long long fc_file_size_for_path(NSString *path)
{
    NSDictionary<NSFileAttributeKey, id> *attrs =
        [NSFileManager.defaultManager attributesOfItemAtPath:path error:nil];
    return [attrs[NSFileSize] unsignedLongLongValue];
}

static NSArray<NSString *> *fc_app_bundle_roots(void)
{
    return @[
        @"/var/containers/Bundle/Application",
        @"/private/var/containers/Bundle/Application",
    ];
}

static NSString *fc_clean_path_component(NSString *s)
{
    if (![s isKindOfClass:NSString.class] || s.length == 0) return @"_";
    NSMutableString *out = [NSMutableString stringWithCapacity:s.length];
    NSCharacterSet *allowed =
        [NSCharacterSet characterSetWithCharactersInString:@"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"];
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        [out appendString:[allowed characterIsMember:c] ? [NSString stringWithCharacters:&c length:1] : @"_"];
    }
    return out.length ? out : @"_";
}

static NSDictionary<NSString *, NSString *> *fc_app_info_for_bundle_path(NSString *bundlePath)
{
    NSString *infoPath = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
    NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
    NSString *bundleID = [info[@"CFBundleIdentifier"] isKindOfClass:NSString.class]
        ? info[@"CFBundleIdentifier"] : @"";
    if (bundleID.length == 0) return nil;
    NSString *name = [info[@"CFBundleDisplayName"] isKindOfClass:NSString.class]
        ? info[@"CFBundleDisplayName"] : nil;
    if (name.length == 0 && [info[@"CFBundleName"] isKindOfClass:NSString.class]) {
        name = info[@"CFBundleName"];
    }
    if (name.length == 0) name = bundleID;
    return @{
        @"bundleID": bundleID,
        @"name": name,
        @"bundlePath": bundlePath.stringByStandardizingPath ?: bundlePath,
    };
}

static NSArray<NSDictionary<NSString *, NSString *> *> *fc_legacy_installed_apps(void)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableDictionary<NSString *, NSDictionary<NSString *, NSString *> *> *byBundle =
        [NSMutableDictionary dictionary];

    for (NSString *root in fc_app_bundle_roots()) {
        NSArray<NSString *> *uuidDirs = [fm contentsOfDirectoryAtPath:root error:nil];
        for (NSString *uuidDir in uuidDirs) {
            NSString *uuidPath = [root stringByAppendingPathComponent:uuidDir];
            BOOL isDir = NO;
            if (![fm fileExistsAtPath:uuidPath isDirectory:&isDir] || !isDir) continue;
            NSArray<NSString *> *children = [fm contentsOfDirectoryAtPath:uuidPath error:nil];
            for (NSString *child in children) {
                if (![child.pathExtension.lowercaseString isEqualToString:@"app"]) continue;
                NSString *bundlePath = [uuidPath stringByAppendingPathComponent:child];
                NSDictionary<NSString *, NSString *> *info = fc_app_info_for_bundle_path(bundlePath);
                NSString *bundleID = info[@"bundleID"];
                if (bundleID.length == 0 || byBundle[bundleID]) continue;
                byBundle[bundleID] = info;
            }
        }
    }

    NSArray *apps = byBundle.allValues;
    return [apps sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        NSString *an = a[@"name"] ?: a[@"bundleID"] ?: @"";
        NSString *bn = b[@"name"] ?: b[@"bundleID"] ?: @"";
        NSComparisonResult r = [an localizedCaseInsensitiveCompare:bn];
        if (r != NSOrderedSame) return r;
        return [(a[@"bundleID"] ?: @"") localizedCaseInsensitiveCompare:(b[@"bundleID"] ?: @"")];
    }];
}

static NSDictionary<NSString *, NSString *> *fc_app_info_for_bundle_id(NSString *bundleID)
{
    if (bundleID.length == 0) return nil;
    for (NSDictionary<NSString *, NSString *> *app in fc_legacy_installed_apps()) {
        if ([app[@"bundleID"] isEqualToString:bundleID]) return app;
    }
    return nil;
}

static BOOL fc_path_is_in_legacy_app_root(NSString *path)
{
    if (![path isKindOfClass:NSString.class] || path.length == 0) return NO;
    NSString *resolvedPath = path.stringByStandardizingPath.stringByResolvingSymlinksInPath;
    for (NSString *root in fc_app_bundle_roots()) {
        NSString *resolvedRoot = root.stringByStandardizingPath.stringByResolvingSymlinksInPath;
        if ([resolvedPath hasPrefix:[resolvedRoot stringByAppendingString:@"/"]]) return YES;
    }
    return NO;
}

static void fc_log_app_feature_retired(void)
{
    log_user("[APP-FONT] Per-app font overrides are retired. Global system font apply/restore is unchanged.\n");
}

NSArray<NSDictionary<NSString *, NSString *> *> *font_changer_installed_apps(void)
{
    fc_log_app_feature_retired();
    return @[];
}

void font_changer_select_app(NSString *bundleID, NSString *name, NSString *bundlePath)
{
    (void)bundleID;
    (void)name;
    (void)bundlePath;
    fc_log_app_feature_retired();
}

NSString *font_changer_selected_app_summary(void)
{
    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    NSString *bundleID = [d stringForKey:kFCAppTargetBundleIDKey] ?: @"";
    if (bundleID.length == 0) return @"Per-app font overrides are retired.";
    NSString *name = [d stringForKey:kFCAppTargetNameKey] ?: @"";
    NSString *storedPath = [d stringForKey:kFCAppTargetBundlePathKey] ?: @"";
    NSString *label = name.length ? name : bundleID;
    NSString *recovery = storedPath.length ? @"recovery metadata retained" : @"bundle path unavailable";
    return [NSString stringWithFormat:@"Legacy selection inactive: %@ (%@); %@.",
            label, bundleID, recovery];
}

bool font_changer_diagnose_selected_app(void)
{
    fc_log_app_feature_retired();
    return false;
}

NSString *font_changer_app_override_summary(void)
{
    NSDictionary *overrides = [NSUserDefaults.standardUserDefaults dictionaryForKey:kFCAppOverridesKey];
    if (overrides.count == 0) return @"Per-app font overrides are retired.";
    NSUInteger fontCount = 0;
    for (id value in overrides.allValues) {
        NSDictionary *entry = [value isKindOfClass:NSDictionary.class] ? value : nil;
        NSArray *fonts = [entry[@"fonts"] isKindOfClass:NSArray.class] ? entry[@"fonts"] : @[];
        fontCount += fonts.count;
    }
    return [NSString stringWithFormat:@"%lu legacy app%@ / %lu target%@ retained for restore only.",
            (unsigned long)overrides.count,
            overrides.count == 1 ? @"" : @"s",
            (unsigned long)fontCount,
            fontCount == 1 ? @"" : @"s"];
}

bool font_changer_whitelist_selected_app_fonts(void)
{
    fc_log_app_feature_retired();
    return false;
}

void font_changer_clear_selected_app_override(void)
{
    fc_log_app_feature_retired();
    log_user("[APP-FONT] Legacy recovery metadata was preserved. Restore old app backups before deleting it.\n");
}

static BOOL fc_legacy_relative_path_is_safe(NSString *relative)
{
    if (![relative isKindOfClass:NSString.class] || relative.length == 0 ||
        [relative hasPrefix:@"/"]) {
        return NO;
    }
    for (NSString *component in relative.pathComponents) {
        if ([component isEqualToString:@"/"] || [component isEqualToString:@"."] ||
            [component isEqualToString:@".."] || component.length == 0) {
            return NO;
        }
    }
    return YES;
}

static NSString *fc_app_backup_path(NSString *bundleID, NSString *relative)
{
    NSString *root = [[fc_app_backup_dir() stringByAppendingPathComponent:fc_clean_path_component(bundleID)]
                      stringByStandardizingPath];
    NSArray<NSString *> *components = [relative pathComponents];
    NSString *path = root;
    for (NSUInteger i = 0; i < components.count; i++) {
        NSString *component = components[i];
        if ([component isEqualToString:@"/"] || [component isEqualToString:@"."] ||
            [component isEqualToString:@".."]) {
            continue;
        }
        path = [path stringByAppendingPathComponent:component];
    }
    return [path stringByAppendingString:@".orig"];
}

static NSString *fc_resolved_bundle_path_for_override(NSString *bundleID, NSDictionary *entry)
{
    NSString *saved = [entry[@"bundlePath"] isKindOfClass:NSString.class] ? entry[@"bundlePath"] : @"";
    NSDictionary<NSString *, NSString *> *savedInfo = fc_app_info_for_bundle_path(saved);
    if ([savedInfo[@"bundleID"] isEqualToString:bundleID] &&
        fc_path_is_in_legacy_app_root(savedInfo[@"bundlePath"])) {
        return savedInfo[@"bundlePath"];
    }
    NSDictionary<NSString *, NSString *> *resolved = fc_app_info_for_bundle_id(bundleID);
    NSString *resolvedPath = resolved[@"bundlePath"] ?: @"";
    return fc_path_is_in_legacy_app_root(resolvedPath) ? resolvedPath : @"";
}

static NSArray<NSString *> *fc_legacy_override_bundle_ids(NSDictionary *overrides)
{
    NSMutableArray<NSString *> *bundleIDs = [NSMutableArray array];
    for (id key in overrides) {
        if ([key isKindOfClass:NSString.class] && [key length] > 0) {
            [bundleIDs addObject:key];
        }
    }
    return [bundleIDs sortedArrayUsingSelector:@selector(compare:)];
}

BOOL font_changer_has_legacy_app_backups(void)
{
    NSDictionary *overrides = [NSUserDefaults.standardUserDefaults dictionaryForKey:kFCAppOverridesKey];
    for (NSString *bundleID in fc_legacy_override_bundle_ids(overrides)) {
        NSDictionary *entry = [overrides[bundleID] isKindOfClass:NSDictionary.class] ? overrides[bundleID] : nil;
        NSArray *fonts = [entry[@"fonts"] isKindOfClass:NSArray.class] ? entry[@"fonts"] : @[];
        for (id value in fonts) {
            NSString *relative = [value isKindOfClass:NSString.class] ? value : nil;
            if (fc_legacy_relative_path_is_safe(relative) &&
                fc_file_exists_nonempty(fc_app_backup_path(bundleID, relative))) {
                return YES;
            }
        }
    }
    return NO;
}

static NSString *fc_safe_legacy_app_target(NSString *bundlePath, NSString *relative)
{
    if (![bundlePath isKindOfClass:NSString.class] || bundlePath.length == 0 ||
        !fc_legacy_relative_path_is_safe(relative)) {
        return nil;
    }

    NSString *root = bundlePath.stringByStandardizingPath.stringByResolvingSymlinksInPath;
    NSString *target = [[bundlePath stringByAppendingPathComponent:relative]
                        stringByStandardizingPath].stringByResolvingSymlinksInPath;
    NSString *rootPrefix = [root stringByAppendingString:@"/"];
    return [target hasPrefix:rootPrefix] ? target : nil;
}

bool font_changer_apply_app_overrides(void)
{
    fc_log_app_feature_retired();
    log_user("[APP-FONT] Apply was blocked; no app bundle files were changed.\n");
    return false;
}

bool font_changer_restore_legacy_app_backups(void)
{
    NSDictionary *overrides = [NSUserDefaults.standardUserDefaults dictionaryForKey:kFCAppOverridesKey];
    if (overrides.count == 0) {
        log_user("[APP-FONT] No legacy app font backups are registered for restore.\n");
        return false;
    }

    log_user("[APP-FONT] Starting recovery-only restore for legacy app font overrides.\n");
    NSUInteger restored = 0, skipped = 0, failed = 0;
    for (NSString *bundleID in fc_legacy_override_bundle_ids(overrides)) {
        NSDictionary *entry = [overrides[bundleID] isKindOfClass:NSDictionary.class] ? overrides[bundleID] : nil;
        NSArray *fonts = [entry[@"fonts"] isKindOfClass:NSArray.class] ? entry[@"fonts"] : @[];
        NSString *bundlePath = fc_resolved_bundle_path_for_override(bundleID, entry);
        if (bundlePath.length == 0) {
            log_user("[APP-FONT] Skip legacy restore for %s: installed bundle path not found.\n",
                     bundleID.UTF8String);
            skipped += fonts.count;
            continue;
        }
        for (id value in fonts) {
            NSString *relative = [value isKindOfClass:NSString.class] ? value : nil;
            NSString *target = fc_safe_legacy_app_target(bundlePath, relative);
            if (target.length == 0) {
                log_user("[APP-FONT] Skip unsafe legacy target for %s.\n", bundleID.UTF8String);
                skipped++;
                continue;
            }
            NSString *backup = fc_app_backup_path(bundleID, relative);
            if (!fc_file_exists_nonempty(backup)) {
                log_user("[APP-FONT] No backup for %s %s\n",
                         bundleID.UTF8String, relative.UTF8String);
                skipped++;
                continue;
            }
            if (!fc_preflight_pair(@"App", backup, target)) {
                failed++;
                continue;
            }
            if (fc_overwrite(target, backup, [NSString stringWithFormat:@"App font restore %@", bundleID])) {
                restored++;
            } else {
                failed++;
            }
        }
    }

    log_user("[APP-FONT] Legacy restore complete restored=%lu skipped=%lu failed=%lu. Recovery metadata was retained; force quit/reopen affected apps.\n",
             (unsigned long)restored, (unsigned long)skipped, (unsigned long)failed);
    return restored > 0 && failed == 0;
}

bool font_changer_restore_app_overrides(void)
{
    return font_changer_restore_legacy_app_backups();
}

static NSString *fc_string_or_dash(id obj)
{
    if ([obj isKindOfClass:NSString.class] && [obj length] > 0) return obj;
    if ([obj respondsToSelector:@selector(stringValue)]) return [obj stringValue];
    return @"-";
}

static BOOL fc_read_u16(NSData *data, NSUInteger off, uint16_t *out)
{
    if (off > data.length || data.length - off < 2) return NO;
    const uint8_t *b = data.bytes;
    if (out) *out = ((uint16_t)b[off] << 8) | b[off + 1];
    return YES;
}

static BOOL fc_read_u32(NSData *data, NSUInteger off, uint32_t *out)
{
    if (off > data.length || data.length - off < 4) return NO;
    const uint8_t *b = data.bytes;
    if (out) {
        *out = ((uint32_t)b[off] << 24) |
               ((uint32_t)b[off + 1] << 16) |
               ((uint32_t)b[off + 2] << 8) |
               (uint32_t)b[off + 3];
    }
    return YES;
}

static BOOL fc_read_s32(NSData *data, NSUInteger off, int32_t *out)
{
    uint32_t u = 0;
    if (!fc_read_u32(data, off, &u)) return NO;
    if (out) *out = (int32_t)u;
    return YES;
}

static NSString *fc_tag_string(uint32_t tag)
{
    char chars[5] = {
        (char)((tag >> 24) & 0xff),
        (char)((tag >> 16) & 0xff),
        (char)((tag >> 8) & 0xff),
        (char)(tag & 0xff),
        '\0'
    };
    for (int i = 0; i < 4; i++) {
        if (chars[i] < 32 || chars[i] > 126) chars[i] = '?';
    }
    return [NSString stringWithUTF8String:chars] ?: @"????";
}

static NSArray<NSNumber *> *fc_face_offsets(NSData *data)
{
    uint32_t header = 0;
    if (!fc_read_u32(data, 0, &header)) return @[];

    if ([fc_tag_string(header) isEqualToString:@"ttcf"]) {
        uint32_t count = 0;
        if (!fc_read_u32(data, 8, &count) || count == 0 || count > 64) return @[];
        NSMutableArray<NSNumber *> *offsets = [NSMutableArray arrayWithCapacity:count];
        for (uint32_t i = 0; i < count; i++) {
            uint32_t off = 0;
            if (!fc_read_u32(data, 12 + ((NSUInteger)i * 4), &off)) break;
            if ((NSUInteger)off <= data.length && data.length - (NSUInteger)off >= 12) {
                [offsets addObject:@(off)];
            }
        }
        return offsets;
    }

    return data.length >= 12 ? @[ @0 ] : @[];
}

static NSDictionary<NSString *, NSDictionary<NSString *, NSNumber *> *> *fc_table_map(NSData *data,
                                                                                       NSUInteger faceOffset,
                                                                                       uint32_t *sfntVersionOut)
{
    uint32_t sfntVersion = 0;
    uint16_t numTables = 0;
    if (!fc_read_u32(data, faceOffset, &sfntVersion) ||
        !fc_read_u16(data, faceOffset + 4, &numTables) ||
        numTables == 0 || numTables > 512) {
        return @{};
    }
    if (sfntVersionOut) *sfntVersionOut = sfntVersion;

    NSMutableDictionary<NSString *, NSDictionary<NSString *, NSNumber *> *> *tables =
        [NSMutableDictionary dictionaryWithCapacity:numTables];
    for (uint16_t i = 0; i < numTables; i++) {
        NSUInteger rec = faceOffset + 12 + ((NSUInteger)i * 16);
        uint32_t tag = 0, off = 0, len = 0;
        if (!fc_read_u32(data, rec, &tag) ||
            !fc_read_u32(data, rec + 8, &off) ||
            !fc_read_u32(data, rec + 12, &len)) {
            continue;
        }
        if ((NSUInteger)off > data.length || (NSUInteger)len > data.length - (NSUInteger)off) {
            continue;
        }
        tables[fc_tag_string(tag)] = @{ @"offset": @(off), @"length": @(len) };
    }
    return tables;
}

static NSString *fc_table_tags_summary(NSDictionary<NSString *, NSDictionary<NSString *, NSNumber *> *> *tables)
{
    NSArray<NSString *> *tags = [tables.allKeys sortedArrayUsingSelector:@selector(compare:)];
    if (tags.count == 0) return @"none";

    NSMutableArray<NSString *> *interesting = [NSMutableArray array];
    for (NSString *tag in @[@"name", @"fvar", @"STAT", @"avar", @"OS/2", @"post", @"CFF ", @"CFF2", @"gvar"]) {
        if ([tags containsObject:tag]) [interesting addObject:tag];
    }
    NSString *prefix = interesting.count > 0
        ? [NSString stringWithFormat:@"interesting=%@", [interesting componentsJoinedByString:@","]]
        : @"interesting=none";
    NSUInteger limit = MIN((NSUInteger)24, tags.count);
    NSArray<NSString *> *sample = [tags subarrayWithRange:NSMakeRange(0, limit)];
    NSString *tail = tags.count > limit
        ? [NSString stringWithFormat:@",...(+%lu)", (unsigned long)(tags.count - limit)]
        : @"";
    return [NSString stringWithFormat:@"%@ all=%@%@", prefix,
            [sample componentsJoinedByString:@","], tail];
}

static NSString *fc_clean_font_string(NSString *s)
{
    if (s.length == 0) return @"";
    NSCharacterSet *newlines = [NSCharacterSet newlineCharacterSet];
    NSString *clean = [[s componentsSeparatedByCharactersInSet:newlines] componentsJoinedByString:@" "];
    clean = [clean stringByReplacingOccurrencesOfString:@"\t" withString:@" "];
    if (clean.length > 96) clean = [[clean substringToIndex:96] stringByAppendingString:@"..."];
    return clean;
}

static NSString *fc_decode_name_string(NSData *data, NSUInteger off, NSUInteger len,
                                       uint16_t platformID)
{
    if (off > data.length || len > data.length - off || len == 0) return @"";
    const void *bytes = ((const uint8_t *)data.bytes) + off;
    NSStringEncoding enc = (platformID == 0 || platformID == 3)
        ? NSUTF16BigEndianStringEncoding
        : NSMacOSRomanStringEncoding;
    NSString *s = [[NSString alloc] initWithBytes:bytes length:len encoding:enc];
    if (s.length == 0 && enc != NSUTF8StringEncoding) {
        s = [[NSString alloc] initWithBytes:bytes length:len encoding:NSUTF8StringEncoding];
    }
    return fc_clean_font_string(s ?: @"");
}

static BOOL fc_name_id_wanted(uint16_t nameID)
{
    return nameID == 1 || nameID == 2 || nameID == 4 ||
           nameID == 6 || nameID == 16 || nameID == 17;
}

static NSDictionary<NSNumber *, NSString *> *fc_parse_name_table(NSData *data,
                                                                  NSDictionary<NSString *, NSNumber *> *table)
{
    NSUInteger tableOff = table[@"offset"].unsignedIntegerValue;
    NSUInteger tableLen = table[@"length"].unsignedIntegerValue;
    if (tableOff > data.length || tableLen > data.length - tableOff || tableLen < 6) return @{};

    uint16_t count = 0, stringOffset = 0;
    if (!fc_read_u16(data, tableOff + 2, &count) ||
        !fc_read_u16(data, tableOff + 4, &stringOffset) ||
        count > 2048) {
        return @{};
    }

    NSUInteger storage = tableOff + stringOffset;
    NSMutableDictionary<NSNumber *, NSString *> *out = [NSMutableDictionary dictionary];
    for (uint16_t i = 0; i < count; i++) {
        NSUInteger rec = tableOff + 6 + ((NSUInteger)i * 12);
        uint16_t platformID = 0, nameID = 0, length = 0, offset = 0;
        if (!fc_read_u16(data, rec, &platformID) ||
            !fc_read_u16(data, rec + 6, &nameID) ||
            !fc_read_u16(data, rec + 8, &length) ||
            !fc_read_u16(data, rec + 10, &offset)) {
            continue;
        }
        if (!fc_name_id_wanted(nameID)) continue;
        NSString *s = fc_decode_name_string(data, storage + offset, length, platformID);
        if (s.length == 0) continue;

        NSNumber *key = @(nameID);
        NSString *old = out[key];
        if (old.length == 0 || platformID == 3 || platformID == 0) {
            out[key] = s;
        }
    }
    return out;
}

static NSString *fc_name_value(NSDictionary<NSNumber *, NSString *> *names, uint16_t nameID)
{
    return fc_string_or_dash(names[@(nameID)]);
}

static double fc_fixed_16_16(int32_t raw)
{
    return ((double)raw) / 65536.0;
}

static void fc_log_os2_weight(NSData *data, NSDictionary<NSString *, NSNumber *> *table)
{
    NSUInteger off = table[@"offset"].unsignedIntegerValue;
    uint16_t weight = 0, width = 0;
    if (fc_read_u16(data, off + 4, &weight) &&
        fc_read_u16(data, off + 6, &width)) {
        log_user("[FONT-DIAG]     OS/2 weightClass=%u widthClass=%u\n",
                 weight, width);
    }
}

static void fc_log_fvar_axes(NSData *data,
                             NSDictionary<NSString *, NSNumber *> *table,
                             NSDictionary<NSNumber *, NSString *> *names)
{
    if (!table) {
        log_user("[FONT-DIAG]     variationAxes=none\n");
        return;
    }

    NSUInteger tableOff = table[@"offset"].unsignedIntegerValue;
    NSUInteger tableLen = table[@"length"].unsignedIntegerValue;
    uint16_t axesOffset = 0, axisCount = 0, axisSize = 0;
    if (tableLen < 16 ||
        !fc_read_u16(data, tableOff + 4, &axesOffset) ||
        !fc_read_u16(data, tableOff + 8, &axisCount) ||
        !fc_read_u16(data, tableOff + 10, &axisSize) ||
        axisCount > 64 || axisSize < 20) {
        log_user("[FONT-DIAG]     variationAxes=fvar-present-unreadable\n");
        return;
    }

    log_user("[FONT-DIAG]     variationAxes=%u\n", axisCount);
    for (uint16_t i = 0; i < axisCount; i++) {
        NSUInteger rec = tableOff + axesOffset + ((NSUInteger)i * axisSize);
        uint32_t tag = 0;
        int32_t minRaw = 0, defRaw = 0, maxRaw = 0;
        uint16_t axisNameID = 0;
        if (!fc_read_u32(data, rec, &tag) ||
            !fc_read_s32(data, rec + 4, &minRaw) ||
            !fc_read_s32(data, rec + 8, &defRaw) ||
            !fc_read_s32(data, rec + 12, &maxRaw) ||
            !fc_read_u16(data, rec + 18, &axisNameID)) {
            continue;
        }
        NSString *axisName = fc_name_value(names, axisNameID);
        log_user("[FONT-DIAG]       axis tag=%s name=\"%s\" min=%.3f default=%.3f max=%.3f\n",
                 fc_tag_string(tag).UTF8String,
                 axisName.UTF8String,
                 fc_fixed_16_16(minRaw),
                 fc_fixed_16_16(defRaw),
                 fc_fixed_16_16(maxRaw));
    }
}

static void fc_log_font_face_diagnostics(NSData *data, NSUInteger faceOffset, NSUInteger faceIndex)
{
    uint32_t sfntVersion = 0;
    NSDictionary<NSString *, NSDictionary<NSString *, NSNumber *> *> *tables =
        fc_table_map(data, faceOffset, &sfntVersion);
    log_user("[FONT-DIAG]   face[%lu] offset=%lu sfnt=%s tables{%s}\n",
             (unsigned long)faceIndex,
             (unsigned long)faceOffset,
             fc_tag_string(sfntVersion).UTF8String,
             fc_table_tags_summary(tables).UTF8String);

    NSDictionary<NSNumber *, NSString *> *names = fc_parse_name_table(data, tables[@"name"]);
    log_user("[FONT-DIAG]     names family=\"%s\" style=\"%s\" full=\"%s\" ps=\"%s\" typoFamily=\"%s\" typoStyle=\"%s\"\n",
             fc_name_value(names, 1).UTF8String,
             fc_name_value(names, 2).UTF8String,
             fc_name_value(names, 4).UTF8String,
             fc_name_value(names, 6).UTF8String,
             fc_name_value(names, 16).UTF8String,
             fc_name_value(names, 17).UTF8String);

    if (tables[@"OS/2"]) fc_log_os2_weight(data, tables[@"OS/2"]);
    fc_log_fvar_axes(data, tables[@"fvar"], names);
}

static void fc_log_font_file_diagnostics(NSString *label, NSString *path)
{
    @autoreleasepool {
        if (path.length == 0) {
            log_user("[FONT-DIAG] %s: no path\n", label.UTF8String);
            return;
        }

        BOOL isDir = NO;
        BOOL exists = [NSFileManager.defaultManager fileExistsAtPath:path isDirectory:&isDir];
        unsigned long long size = exists && !isDir ? fc_file_size_for_path(path) : 0;
        log_user("[FONT-DIAG] %s path=%s exists=%d dir=%d size=%llu\n",
                 label.UTF8String, path.UTF8String, exists, isDir, size);
        if (!exists || isDir || size == 0) return;

        NSData *data = [NSData dataWithContentsOfFile:path
                                              options:NSDataReadingMappedIfSafe
                                                error:nil];
        if (data.length == 0) {
            data = [NSData dataWithContentsOfFile:path];
        }
        if (data.length == 0) {
            log_user("[FONT-DIAG] %s read failed.\n", label.UTF8String);
            return;
        }

        NSArray<NSNumber *> *faces = fc_face_offsets(data);
        log_user("[FONT-DIAG] %s rawParse faces=%lu\n",
                 label.UTF8String, (unsigned long)faces.count);
        if (faces.count == 0) {
            log_user("[FONT-DIAG] %s is not a readable TTF/OTF/TTC SFNT file.\n",
                     label.UTF8String);
            return;
        }
        for (NSUInteger i = 0; i < faces.count; i++) {
            fc_log_font_face_diagnostics(data, faces[i].unsignedIntegerValue, i);
        }
        return;
    }
}

void font_changer_log_stock_diagnostics(void)
{
    log_user("[FONT-DIAG] Inspecting stock SFUI targets.\n");
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        NSString *label = [NSString stringWithFormat:@"stock %@", kFCRoles[i].displayName];
        fc_log_font_file_diagnostics(label, kFCRoles[i].targetPath);
    }
    log_user("[FONT-DIAG] Stock inspection complete.\n");
}

void font_changer_log_selected_diagnostics(void)
{
    log_user("[FONT-DIAG] Inspecting imported selected fonts.\n");
    for (NSUInteger i = 0; i < fc_role_count(); i++) {
        NSString *path = fc_selected_path_for_role(kFCRoles[i].role);
        NSString *label = [NSString stringWithFormat:@"selected %@", kFCRoles[i].displayName];
        fc_log_font_file_diagnostics(label, path);
    }
    log_user("[FONT-DIAG] Imported font inspection complete.\n");
}
