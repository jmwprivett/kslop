//
//  snowboardlite.m
//  Cyanide
//  Adapted from https://github.com/d1y/cyanide-ios (AGPL-3.0).
//

#import "snowboardlite.h"
#import "../installer/CNDSnowBoardRemix.h"
#import "../LogTextView.h"
#import "../SettingsViewController.h"
#import "../map_app.h"
#import <ImageIO/ImageIO.h>

NSString * const kSnowBoardLiteThemeBuiltinIOS6 = @"builtin-ios6";
NSString * const kSettingsSnowBoardRemixDebugThreeAppLimit =
    @"SnowBoardRemixDebugThreeAppLimit";
NSString * const kSettingsSnowBoardRemixInstallConsumerMappings =
    @"SnowBoardRemixInstallConsumerMappings";

static NSString *sbl_builtin_ios6_path(void)
{
    return [[NSBundle mainBundle].bundlePath
        stringByAppendingPathComponent:@"Themes-iOS6.plist"];
}

static NSDictionary<NSString *, NSData *> *sbl_load_plist_theme(NSString *plistPath)
{
    NSError *err = nil;
    NSData *raw = [NSData dataWithContentsOfFile:plistPath options:0 error:&err];
    if (!raw) {
        printf("[SBR] resolve: failed to read plist err=%s\n",
               err.localizedDescription.UTF8String ?: "?");
        return nil;
    }
    id parsed = [NSPropertyListSerialization
        propertyListWithData:raw
                     options:NSPropertyListImmutable
                      format:NULL
                       error:&err];
    if (![parsed isKindOfClass:[NSDictionary class]]) {
        printf("[SBR] resolve: plist parse failed err=%s\n",
               err.localizedDescription.UTF8String ?: "?");
        return nil;
    }

    NSMutableDictionary<NSString *, NSData *> *out = [NSMutableDictionary dictionary];
    NSDictionary *dict = (NSDictionary *)parsed;
    for (id key in dict) {
        id value = dict[key];
        if (![key isKindOfClass:NSString.class] ||
            ![value isKindOfClass:NSData.class] ||
            [(NSData *)value length] == 0) {
            continue;
        }
        out[key] = value;
    }

    printf("[SBR] resolve: loaded plist theme entries=%lu size=%lu path=%s\n",
           (unsigned long)out.count,
           (unsigned long)raw.length,
           plistPath.UTF8String);
    return out;
}

static BOOL sbl_png_pixel_area(NSData *data, uint64_t *areaOut)
{
    if (areaOut) *areaOut = 0;
    if (![data isKindOfClass:NSData.class] || data.length == 0) return NO;

    CGImageSourceRef source = CGImageSourceCreateWithData(
        (__bridge CFDataRef)data, NULL);
    if (!source) return NO;
    if (CGImageSourceGetCount(source) == 0 ||
        CGImageSourceGetStatusAtIndex(source, 0) != kCGImageStatusComplete) {
        CFRelease(source);
        return NO;
    }
    CFDictionaryRef propertiesRef =
        CGImageSourceCopyPropertiesAtIndex(source, 0, NULL);
    NSDictionary *properties = (__bridge NSDictionary *)propertiesRef;
    NSNumber *width =
        properties[(__bridge NSString *)kCGImagePropertyPixelWidth];
    NSNumber *height =
        properties[(__bridge NSString *)kCGImagePropertyPixelHeight];
    uint64_t w = [width isKindOfClass:NSNumber.class]
        ? width.unsignedLongLongValue : 0;
    uint64_t h = [height isKindOfClass:NSNumber.class]
        ? height.unsignedLongLongValue : 0;
    if (propertiesRef) CFRelease(propertiesRef);
    CFRelease(source);
    if (w == 0 || h == 0 || w > UINT32_MAX || h > UINT32_MAX) return NO;
    if (areaOut) *areaOut = w * h;
    return YES;
}

static BOOL sbl_icon_candidate_is_better(BOOL candidateValid,
                                         uint64_t candidateArea,
                                         NSUInteger candidateBytes,
                                         NSString *candidateFile,
                                         BOOL currentValid,
                                         uint64_t currentArea,
                                         NSUInteger currentBytes,
                                         NSString *currentFile)
{
    if (candidateValid != currentValid) return candidateValid;
    if (candidateArea != currentArea) return candidateArea > currentArea;
    if (candidateBytes != currentBytes) return candidateBytes > currentBytes;
    if (currentFile.length == 0) return YES;
    NSComparisonResult folded = [candidateFile compare:currentFile
                                               options:NSCaseInsensitiveSearch];
    if (folded != NSOrderedSame) return folded == NSOrderedAscending;
    return [candidateFile compare:currentFile] == NSOrderedAscending;
}

static NSDictionary<NSString *, NSData *> *sbl_load_icons_directory_theme(NSString *iconsPath)
{
    if (iconsPath.length == 0) return @{};

    NSFileManager *fm = NSFileManager.defaultManager;
    BOOL isDir = NO;
    if (![fm fileExistsAtPath:iconsPath isDirectory:&isDir] || !isDir) {
        printf("[SBR] resolve: missing icon directory %s\n",
               iconsPath.UTF8String ?: "");
        return @{};
    }

    NSArray<NSString *> *files = [fm contentsOfDirectoryAtPath:iconsPath error:nil];
    NSMutableDictionary<NSString *, NSData *> *out =
        [NSMutableDictionary dictionaryWithCapacity:files.count];
    NSMutableDictionary<NSString *, NSNumber *> *winnerAreas =
        [NSMutableDictionary dictionaryWithCapacity:files.count];
    NSMutableDictionary<NSString *, NSNumber *> *winnerValid =
        [NSMutableDictionary dictionaryWithCapacity:files.count];
    NSMutableDictionary<NSString *, NSString *> *winnerFiles =
        [NSMutableDictionary dictionaryWithCapacity:files.count];
    NSUInteger pngCount = 0;
    NSUInteger aliasCount = 0;
    NSUInteger directCount = 0;
    NSUInteger duplicateCount = 0;
    NSUInteger replacementCount = 0;
    NSUInteger skipped = 0;
    uint64_t bytesTotal = 0;

    for (NSString *file in files) {
        if (![file.pathExtension.lowercaseString isEqualToString:@"png"]) continue;
        pngCount++;

        BOOL usedAlias = NO;
        BOOL usedDirect = NO;
        NSArray<NSString *> *bundleIDs = CNDMappedIOSBundleIDsForIconName(file, &usedAlias);
        if (bundleIDs.count == 0) {
            NSString *bundle = file.stringByDeletingPathExtension;
            bundleIDs = bundle.length > 0 ? @[bundle] : @[];
            usedDirect = YES;
        }

        NSString *path = [iconsPath stringByAppendingPathComponent:file];
        NSData *data = [NSData dataWithContentsOfFile:path];
        if (data.length == 0) {
            skipped++;
            continue;
        }
        uint64_t candidateArea = 0;
        BOOL candidateValid = sbl_png_pixel_area(data, &candidateArea);

        BOOL added = NO;
        for (NSString *bundleID in bundleIDs) {
            if (bundleID.length == 0) continue;
            NSData *current = out[bundleID];
            BOOL replacing = current != nil;
            if (replacing) {
                duplicateCount++;
                BOOL currentValid = winnerValid[bundleID].boolValue;
                uint64_t currentArea = winnerAreas[bundleID].unsignedLongLongValue;
                if (!sbl_icon_candidate_is_better(
                        candidateValid, candidateArea, data.length, file,
                        currentValid, currentArea, current.length,
                        winnerFiles[bundleID])) {
                    continue;
                }
                replacementCount++;
                bytesTotal -= current.length;
            }
            out[bundleID] = data;
            winnerAreas[bundleID] = @(candidateArea);
            winnerValid[bundleID] = @(candidateValid);
            winnerFiles[bundleID] = file;
            added = YES;
            bytesTotal += data.length;
            if (!replacing && usedAlias) aliasCount++;
            if (!replacing && usedDirect) directCount++;
        }
        if (!added) skipped++;
    }

    printf("[SBR] resolve: loaded directory theme entries=%lu png=%lu aliases=%lu direct=%lu duplicates=%lu replacements=%lu skipped=%lu bytes=%llu path=%s\n",
           (unsigned long)out.count,
           (unsigned long)pngCount,
           (unsigned long)aliasCount,
           (unsigned long)directCount,
           (unsigned long)duplicateCount,
           (unsigned long)replacementCount,
           (unsigned long)skipped,
           (unsigned long long)bytesTotal,
           iconsPath.UTF8String ?: "");
    return out;
}

static NSString *settings_sbl_root_dir(void)
{
    NSArray<NSString *> *docs = NSSearchPathForDirectoriesInDomains(
        NSDocumentDirectory, NSUserDomainMask, YES);
    if (docs.count == 0) return nil;
    return [docs.firstObject stringByAppendingPathComponent:@"SnowBoardLite"];
}

static NSString *settings_sbl_themes_dir(void)
{
    NSString *root = settings_sbl_root_dir();
    return root ? [root stringByAppendingPathComponent:@"Themes"] : nil;
}

static NSString *settings_sbl_manifest_path(void)
{
    NSString *root = settings_sbl_root_dir();
    return root ? [root stringByAppendingPathComponent:@"Manifest.plist"] : nil;
}

NSArray<NSDictionary *> *settings_sbl_load_manifest(void)
{
    NSString *path = settings_sbl_manifest_path();
    NSArray *raw = path ? [NSArray arrayWithContentsOfFile:path] : nil;
    if (![raw isKindOfClass:NSArray.class]) return @[];

    NSMutableArray<NSDictionary *> *out = [NSMutableArray array];
    for (id obj in raw) {
        if (![obj isKindOfClass:NSDictionary.class]) continue;
        NSDictionary *d = obj;
        NSString *themeID = d[@"id"];
        NSString *name = d[@"name"];
        NSString *iconsPath = d[@"iconsPath"];
        if (![themeID isKindOfClass:NSString.class] || themeID.length == 0) continue;
        if (![name isKindOfClass:NSString.class] || name.length == 0) continue;
        if (![iconsPath isKindOfClass:NSString.class] || iconsPath.length == 0) continue;
        [out addObject:d];
    }
    return out;
}

BOOL settings_sbl_save_manifest(NSArray<NSDictionary *> *themes)
{
    NSString *root = settings_sbl_root_dir();
    NSString *path = settings_sbl_manifest_path();
    if (!root || !path) return NO;
    NSFileManager *fm = NSFileManager.defaultManager;
    if (![fm createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:nil]) {
        return NO;
    }
    return [themes writeToFile:path atomically:YES];
}

static NSString *settings_sbl_selected_theme_identifier(void)
{
    NSUserDefaults *defaults = NSUserDefaults.standardUserDefaults;
    // The legacy master flag represented a live SpringBoard loop. Remix is
    // explicit and transaction-driven, so make sure a direct coordinator
    // call cannot resurrect that obsolete behavior before settings startup
    // has had a chance to run its full migration.
    BOOL disabledLegacyFlag = [defaults boolForKey:kSettingsSnowBoardLiteEnabled];
    if (disabledLegacyFlag) {
        [defaults setBool:NO forKey:kSettingsSnowBoardLiteEnabled];
    }
    NSString *selected = [defaults stringForKey:kSettingsSnowBoardRemixSelectedThemeID];
    if (selected.length > 0) {
        if (disabledLegacyFlag) [defaults synchronize];
        return selected;
    }

    // Read the pre-Remix key once so themes imported by older builds remain
    // usable. Documents/SnowBoardLite and its manifest stay in place.
    NSString *legacy = [defaults stringForKey:kSettingsSnowBoardLiteSelectedThemeID];
    if (legacy.length > 0) {
        [defaults setObject:legacy forKey:kSettingsSnowBoardRemixSelectedThemeID];
        [defaults synchronize];
        return legacy;
    }
    if (disabledLegacyFlag) [defaults synchronize];
    return @"";
}

NSDictionary *settings_sbl_selected_theme(void)
{
    NSString *selected = settings_sbl_selected_theme_identifier();
    if (selected.length == 0) return nil;
    if ([selected isEqualToString:kSnowBoardLiteThemeBuiltinIOS6]) return nil;
    for (NSDictionary *theme in settings_sbl_load_manifest()) {
        if ([theme[@"id"] isEqualToString:selected]) return theme;
    }
    return nil;
}

BOOL settings_sbl_selected_builtin_ios6(void)
{
    NSString *selected = settings_sbl_selected_theme_identifier();
    return [selected isEqualToString:kSnowBoardLiteThemeBuiltinIOS6];
}

static NSString *settings_sbl_existing_icons_path(NSString *path)
{
    BOOL isDir = NO;
    if (path.length > 0 &&
        [NSFileManager.defaultManager fileExistsAtPath:path isDirectory:&isDir] &&
        isDir) {
        return path;
    }
    return nil;
}

NSString *settings_sbl_resolved_icons_path_for_theme(NSDictionary *theme)
{
    NSString *iconsPath = settings_sbl_existing_icons_path(theme[@"iconsPath"]);
    if (iconsPath.length > 0) return iconsPath;

    NSString *themeID = theme[@"id"];
    NSString *root = settings_sbl_themes_dir();
    if (themeID.length == 0 || root.length == 0) return nil;

    NSString *candidate = [[root stringByAppendingPathComponent:themeID]
        stringByAppendingPathComponent:@"Icons"];
    return settings_sbl_existing_icons_path(candidate);
}

static NSArray<NSString *> *settings_sbl_preview_bundle_order(void)
{
    return @[
        @"com.apple.mobilesafari",
        @"com.apple.MobileSMS",
        @"com.apple.mobilemail",
        @"com.apple.mobilephone",
        @"com.apple.Music",
        @"com.apple.AppStore",
        @"com.apple.Preferences",
        @"com.apple.camera",
    ];
}

static void settings_sbl_add_preview_image(NSMutableArray<UIImage *> *out,
                                           UIImage *image,
                                           NSUInteger limit)
{
    if (!image || out.count >= limit) return;
    [out addObject:image];
}

static NSArray<UIImage *> *settings_sbl_builtin_preview_images(NSUInteger limit)
{
    if (limit == 0) return @[];
    static NSArray<UIImage *> *cached = nil;
    if (cached.count >= limit) {
        return [cached subarrayWithRange:NSMakeRange(0, limit)];
    }

    NSDictionary<NSString *, NSData *> *dict = sbl_load_plist_theme(sbl_builtin_ios6_path());
    NSMutableArray<UIImage *> *out = [NSMutableArray arrayWithCapacity:limit];
    NSMutableSet<NSString *> *used = [NSMutableSet set];

    for (NSString *bundleID in settings_sbl_preview_bundle_order()) {
        NSData *data = dict[bundleID];
        UIImage *image = data.length > 0 ? [UIImage imageWithData:data] : nil;
        settings_sbl_add_preview_image(out, image, limit);
        if (image) [used addObject:bundleID];
        if (out.count >= limit) {
            cached = [out copy];
            return out;
        }
    }

    NSArray<NSString *> *keys = [dict.allKeys sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
    for (NSString *bundleID in keys) {
        if ([used containsObject:bundleID]) continue;
        NSData *data = dict[bundleID];
        UIImage *image = data.length > 0 ? [UIImage imageWithData:data] : nil;
        settings_sbl_add_preview_image(out, image, limit);
        if (out.count >= limit) break;
    }
    cached = [out copy];
    return out;
}

static NSArray<UIImage *> *settings_sbl_folder_preview_images(NSString *iconsPath, NSUInteger limit)
{
    if (limit == 0 || iconsPath.length == 0) return @[];
    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableArray<UIImage *> *out = [NSMutableArray arrayWithCapacity:limit];
    NSMutableSet<NSString *> *used = [NSMutableSet set];

    for (NSString *bundleID in settings_sbl_preview_bundle_order()) {
        NSString *name = [bundleID stringByAppendingPathExtension:@"png"];
        NSString *path = [iconsPath stringByAppendingPathComponent:name];
        UIImage *image = [UIImage imageWithContentsOfFile:path];
        settings_sbl_add_preview_image(out, image, limit);
        if (image) [used addObject:name.lowercaseString];
        if (out.count >= limit) return out;
    }

    NSArray<NSString *> *files = [[fm contentsOfDirectoryAtPath:iconsPath error:nil]
        sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
    for (NSString *file in files) {
        if (![file.pathExtension.lowercaseString isEqualToString:@"png"]) continue;
        if ([used containsObject:file.lowercaseString]) continue;
        UIImage *image = [UIImage imageWithContentsOfFile:[iconsPath stringByAppendingPathComponent:file]];
        settings_sbl_add_preview_image(out, image, limit);
        if (out.count >= limit) break;
    }
    return out;
}

NSArray<UIImage *> *settings_sbl_preview_images_for_theme(NSDictionary *theme,
                                                          BOOL builtIn,
                                                          NSUInteger limit)
{
    if (builtIn) return settings_sbl_builtin_preview_images(limit);
    NSString *iconsPath = settings_sbl_resolved_icons_path_for_theme(theme);
    return settings_sbl_folder_preview_images(iconsPath, limit);
}

BOOL settings_snowboardlite_has_selected_theme(void)
{
    if (settings_sbl_selected_builtin_ios6()) {
        return [[NSFileManager defaultManager] fileExistsAtPath:sbl_builtin_ios6_path()];
    }
    NSDictionary *theme = settings_sbl_selected_theme();
    return settings_sbl_resolved_icons_path_for_theme(theme).length > 0;
}

NSString *settings_snowboardlite_selected_theme_display_name(void)
{
    if (settings_sbl_selected_builtin_ios6()) return @"iOS 6 Theme";
    NSDictionary *theme = settings_sbl_selected_theme();
    NSString *name = theme[@"name"];
    return name.length > 0 ? name : @"None";
}

static NSArray<NSURL *> *settings_sbl_iconbundles_dirs_in_folder(NSURL *rootURL)
{
    NSMutableArray<NSURL *> *dirs = [NSMutableArray array];
    if ([rootURL.lastPathComponent caseInsensitiveCompare:@"IconBundles"] == NSOrderedSame) {
        [dirs addObject:rootURL];
    }
    NSDirectoryEnumerator<NSURL *> *e =
        [NSFileManager.defaultManager enumeratorAtURL:rootURL
                           includingPropertiesForKeys:@[NSURLIsDirectoryKey]
                                              options:0
                                         errorHandler:^BOOL(NSURL *url, NSError *error) {
        printf("[SBR] scan skipped %s err=%s\n",
               url.path.UTF8String, error.localizedDescription.UTF8String);
        return YES;
    }];
    for (NSURL *url in e) {
        NSNumber *isDir = nil;
        [url getResourceValue:&isDir forKey:NSURLIsDirectoryKey error:nil];
        if (!isDir.boolValue) continue;
        if ([url.lastPathComponent caseInsensitiveCompare:@"IconBundles"] == NSOrderedSame) {
            [dirs addObject:url];
            [e skipDescendants];
        }
    }
    return dirs;
}

static NSArray<NSURL *> *settings_sbl_springboard_bundle_dirs_in_folder(
    NSURL *rootURL)
{
    NSMutableArray<NSURL *> *dirs = [NSMutableArray array];
    NSFileManager *fm = NSFileManager.defaultManager;
    BOOL isDirectory = NO;
    if ([fm fileExistsAtPath:rootURL.path isDirectory:&isDirectory] &&
        isDirectory &&
        [rootURL.lastPathComponent
            caseInsensitiveCompare:@"com.apple.springboard"] ==
            NSOrderedSame &&
        [rootURL.URLByDeletingLastPathComponent.lastPathComponent
            caseInsensitiveCompare:@"Bundles"] == NSOrderedSame) {
        [dirs addObject:rootURL];
    }
    NSDirectoryEnumerator<NSURL *> *enumerator =
        [fm enumeratorAtURL:rootURL
 includingPropertiesForKeys:@[NSURLIsDirectoryKey]
                    options:NSDirectoryEnumerationSkipsHiddenFiles
               errorHandler:^BOOL(NSURL *url, NSError *error) {
        printf("[SBR] dynamic asset scan skipped %s err=%s\n",
               url.path.UTF8String ?: "",
               error.localizedDescription.UTF8String ?: "");
        return YES;
    }];
    for (NSURL *url in enumerator) {
        NSNumber *directory = nil;
        [url getResourceValue:&directory forKey:NSURLIsDirectoryKey error:nil];
        if (!directory.boolValue ||
            [url.lastPathComponent
                caseInsensitiveCompare:@"com.apple.springboard"] !=
                NSOrderedSame ||
            [url.URLByDeletingLastPathComponent.lastPathComponent
                caseInsensitiveCompare:@"Bundles"] != NSOrderedSame) {
            continue;
        }
        [dirs addObject:url];
        [enumerator skipDescendants];
    }
    return [dirs sortedArrayUsingComparator:^NSComparisonResult(
        NSURL *left, NSURL *right) {
        return [left.path compare:right.path
                          options:NSCaseInsensitiveSearch];
    }];
}

static NSUInteger settings_sbl_import_live_clock_assets(
    NSURL *themeRootURL, NSString *iconsPath)
{
    if (!themeRootURL || iconsPath.length == 0) return 0;
    static NSDictionary<NSString *, NSString *> *assetNames;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        assetNames = @{
            @"ClockIconHourHand@2x.png": @"__cnd_clock_hours.png",
            @"ClockIconMinuteHand@2x.png": @"__cnd_clock_minutes.png",
            @"ClockIconSecondHand@2x.png": @"__cnd_clock_seconds.png",
            @"ClockIconBlackDot@2x.png": @"__cnd_clock_hour_minute_dot.png",
            @"ClockIconRedDot@2x.png": @"__cnd_clock_second_dot.png",
        };
    });

    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableSet<NSString *> *imported = [NSMutableSet set];
    for (NSURL *bundleDirectory in
         settings_sbl_springboard_bundle_dirs_in_folder(themeRootURL)) {
        for (NSString *sourceName in assetNames) {
            NSString *destinationName = assetNames[sourceName];
            if ([imported containsObject:destinationName]) continue;
            NSURL *sourceURL = [bundleDirectory
                URLByAppendingPathComponent:sourceName isDirectory:NO];
            NSData *data = [NSData dataWithContentsOfURL:sourceURL];
            uint64_t area = 0;
            if (data.length == 0 || !sbl_png_pixel_area(data, &area) ||
                area == 0) {
                continue;
            }
            NSString *destination = [iconsPath
                stringByAppendingPathComponent:destinationName];
            if ([data writeToFile:destination
                          options:NSDataWritingAtomic
                            error:nil]) {
                [imported addObject:destinationName];
            }
        }

        /* SnowBoard Clock themes commonly include both an old opaque square
         * face and the transparent iPhone face actually used by the live
         * Clock. Prefer the device-qualified empty face deterministically;
         * the generic files are compatibility fallbacks only. */
        if (![imported containsObject:@"__cnd_clock_background.png"]) {
            for (NSString *sourceName in @[
                    @"ClockIconBackgroundSquare@3x~iphone.png",
                    @"ClockIconBackgroundSquare@2x~iphone.png",
                    @"ClockIconBackgroundSquare~iphone.png",
                    @"ClockIconBackgroundSquare@3x.png",
                    @"ClockIconBackgroundSquare@2x.png",
                    @"ClockIconBackgroundSquare.png"]) {
                NSURL *sourceURL = [bundleDirectory
                    URLByAppendingPathComponent:sourceName isDirectory:NO];
                NSData *data = [NSData dataWithContentsOfURL:sourceURL];
                uint64_t area = 0;
                if (data.length == 0 || !sbl_png_pixel_area(data, &area) ||
                    area == 0) {
                    continue;
                }
                NSString *destination = [iconsPath
                    stringByAppendingPathComponent:
                        @"__cnd_clock_background.png"];
                if ([data writeToFile:destination
                              options:NSDataWritingAtomic
                                error:nil]) {
                    [imported addObject:@"__cnd_clock_background.png"];
                }
                break;
            }
        }
    }
    return imported.count;
}

BOOL settings_sbl_import_folder_theme_named(NSURL *url,
                                            NSString *displayName,
                                            NSString *sourceType,
                                            NSError **error)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSArray<NSURL *> *iconDirs = settings_sbl_iconbundles_dirs_in_folder(url);
    if (iconDirs.count == 0) {
        if (error) {
            *error = [NSError errorWithDomain:@"SnowBoardLite"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"No IconBundles directory was found in this folder."}];
        }
        return NO;
    }

    NSString *root = settings_sbl_themes_dir();
    if (!root) return NO;
    [fm createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:error];
    if (error && *error) return NO;

    NSString *baseName = displayName.length ? displayName :
        (url.lastPathComponent.length ? url.lastPathComponent : @"Imported Theme");
    NSString *themeID = [NSString stringWithFormat:@"sbl-%llu",
                         (unsigned long long)(NSDate.date.timeIntervalSince1970 * 1000.0)];
    NSString *themeDir = [root stringByAppendingPathComponent:themeID];
    NSString *iconsDir = [themeDir stringByAppendingPathComponent:@"Icons"];
    [fm removeItemAtPath:themeDir error:nil];
    [fm createDirectoryAtPath:iconsDir withIntermediateDirectories:YES attributes:nil error:error];
    if (error && *error) return NO;

    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    NSMutableDictionary<NSString *, NSNumber *> *winnerAreas =
        [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSNumber *> *winnerValid =
        [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSNumber *> *winnerBytes =
        [NSMutableDictionary dictionary];
    NSMutableDictionary<NSString *, NSString *> *winnerFiles =
        [NSMutableDictionary dictionary];
    NSMutableArray<NSString *> *skippedSamples = [NSMutableArray array];
    NSUInteger discovered = 0;
    NSUInteger imported = 0;
    NSUInteger aliasMapped = 0;
    NSUInteger duplicates = 0;
    NSUInteger replacements = 0;
    NSUInteger skipped = 0;
    for (NSURL *iconDirURL in iconDirs) {
        NSArray<NSURL *> *files = [fm contentsOfDirectoryAtURL:iconDirURL
                                    includingPropertiesForKeys:nil
                                                       options:0
                                                         error:nil];
        for (NSURL *fileURL in files) {
            if (![fileURL.pathExtension.lowercaseString isEqualToString:@"png"]) continue;
            discovered++;
            BOOL usedAlias = NO;
            NSArray<NSString *> *bundleIDs = CNDMappedIOSBundleIDsForIconName(fileURL.lastPathComponent,
                                                                              &usedAlias);
            if (bundleIDs.count == 0) {
                skipped++;
                if (skippedSamples.count < 8) {
                    [skippedSamples addObject:fileURL.lastPathComponent ?: @"unknown.png"];
                }
                continue;
            }
            NSData *candidateData = [NSData dataWithContentsOfURL:fileURL];
            if (candidateData.length == 0) {
                skipped++;
                if (skippedSamples.count < 8) {
                    [skippedSamples addObject:[NSString stringWithFormat:
                        @"%@ (read failed)",
                        fileURL.lastPathComponent ?: @"unknown.png"]];
                }
                continue;
            }
            uint64_t candidateArea = 0;
            BOOL candidateValid = sbl_png_pixel_area(candidateData,
                                                      &candidateArea);
            NSString *candidateScoreName = fileURL.path.length > 0
                ? fileURL.path : (fileURL.lastPathComponent ?: @"");
            NSMutableSet<NSString *> *fileTargets = [NSMutableSet setWithCapacity:bundleIDs.count];
            BOOL copiedAny = NO;
            for (NSString *bundleID in bundleIDs) {
                if (bundleID.length == 0 || [fileTargets containsObject:bundleID]) continue;
                [fileTargets addObject:bundleID];
                BOOL replacing = [seen containsObject:bundleID];
                if (replacing) {
                    duplicates++;
                    if (!sbl_icon_candidate_is_better(
                            candidateValid,
                            candidateArea,
                            candidateData.length,
                            candidateScoreName,
                            winnerValid[bundleID].boolValue,
                            winnerAreas[bundleID].unsignedLongLongValue,
                            winnerBytes[bundleID].unsignedIntegerValue,
                            winnerFiles[bundleID])) {
                        skipped++;
                        if (skippedSamples.count < 8) {
                            [skippedSamples addObject:[NSString stringWithFormat:@"%@ (lower-resolution duplicate %@)",
                                                       fileURL.lastPathComponent ?: @"unknown.png",
                                                       bundleID]];
                        }
                        continue;
                    }
                }
                NSString *dstName = [bundleID stringByAppendingPathExtension:@"png"];
                NSString *dst = [iconsDir stringByAppendingPathComponent:dstName];
                if ([candidateData writeToFile:dst
                                       options:NSDataWritingAtomic
                                         error:nil]) {
                    [seen addObject:bundleID];
                    winnerAreas[bundleID] = @(candidateArea);
                    winnerValid[bundleID] = @(candidateValid);
                    winnerBytes[bundleID] = @(candidateData.length);
                    winnerFiles[bundleID] = candidateScoreName;
                    copiedAny = YES;
                    if (replacing) {
                        replacements++;
                    } else {
                        imported++;
                        if (usedAlias) aliasMapped++;
                    }
                } else {
                    skipped++;
                    if (skippedSamples.count < 8) {
                        [skippedSamples addObject:[NSString stringWithFormat:@"%@ (copy failed)",
                                                   fileURL.lastPathComponent ?: @"unknown.png"]];
                    }
                }
            }
            if (!copiedAny && fileTargets.count == 0) skipped++;
        }
    }

    NSUInteger liveClockAssets =
        settings_sbl_import_live_clock_assets(url, iconsDir);

    if (imported == 0) {
        [fm removeItemAtPath:themeDir error:nil];
        if (error) {
            *error = [NSError errorWithDomain:@"SnowBoardLite"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: @"IconBundles was found, but no bundle-ID PNG icons could be imported."}];
        }
        return NO;
    }

    NSDateFormatter *fmt = [[NSDateFormatter alloc] init];
    fmt.dateFormat = @"yyyy-MM-dd HH:mm";
    NSDictionary *record = @{
        @"id": themeID,
        @"name": baseName,
        @"sourceType": sourceType.length ? sourceType : @"folder",
        @"sourceName": baseName,
        @"importedAt": [fmt stringFromDate:NSDate.date],
        @"path": themeDir,
        @"iconsPath": iconsDir,
        @"iconCount": @(imported),
        @"discoveredCount": @(discovered),
        @"iconBundlesCount": @(iconDirs.count),
        @"aliasMappedCount": @(aliasMapped),
        @"duplicateCount": @(duplicates),
        @"replacementCount": @(replacements),
        @"liveClockAssetCount": @(liveClockAssets),
        @"skippedCount": @(skipped),
        @"skippedSamples": skippedSamples,
    };
    NSMutableArray *manifest = [settings_sbl_load_manifest() mutableCopy];
    [manifest insertObject:record atIndex:0];
    if (!settings_sbl_save_manifest(manifest)) return NO;

    NSUserDefaults *d = NSUserDefaults.standardUserDefaults;
    [d setObject:themeID forKey:kSettingsSnowBoardRemixSelectedThemeID];
    [d synchronize];
    log_user("[SBR] Imported \"%s\": %lu icons from %lu IconBundles folder(s), aliases=%lu skipped=%lu duplicates=%lu replacements=%lu live-clock-assets=%lu.\n",
             baseName.UTF8String,
             (unsigned long)imported,
             (unsigned long)iconDirs.count,
             (unsigned long)aliasMapped,
             (unsigned long)skipped,
             (unsigned long)duplicates,
             (unsigned long)replacements,
             (unsigned long)liveClockAssets);
    if (skippedSamples.count > 0) {
        log_user("[SBR] Skipped sample: %s\n",
                 [skippedSamples componentsJoinedByString:@", "].UTF8String);
    }
    return YES;
}

BOOL settings_sbl_import_folder_theme(NSURL *url, NSError **error)
{
    return settings_sbl_import_folder_theme_named(url, url.lastPathComponent, @"folder", error);
}

static NSDictionary<NSString *, NSData *> *settings_sbl_selected_theme_data_locked(NSUserDefaults *d)
{
    if (settings_sbl_selected_builtin_ios6()) {
        NSString *plistPath = sbl_builtin_ios6_path();
        if (![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
            log_user("[SBR] Bundled iOS 6 Theme plist is missing.\n");
            return nil;
        }
        return sbl_load_plist_theme(plistPath);
    }

    NSDictionary *theme = settings_sbl_selected_theme();
    NSString *iconsPath = settings_sbl_resolved_icons_path_for_theme(theme);
    if (iconsPath.length == 0) {
        log_user("[SBR] Pick an imported theme before running SBR.\n");
        return nil;
    }
    printf("[SBR] applying theme=%s icons=%s\n",
           [theme[@"name"] UTF8String] ?: "?",
           iconsPath.UTF8String);
    return sbl_load_icons_directory_theme(iconsPath);
}

NSDictionary<NSString *, NSData *> *settings_sbl_selected_theme_data(void)
{
    return settings_sbl_selected_theme_data_locked(NSUserDefaults.standardUserDefaults);
}

static void settings_sbl_log_remix_progress(NSString *phase,
                                            NSUInteger completed,
                                            NSUInteger total,
                                            NSString *bundleIdentifier)
{
    NSString *phaseName = [phase isKindOfClass:NSString.class] && phase.length > 0
        ? phase : @"working";
    NSString *target = [bundleIdentifier isKindOfClass:NSString.class]
        ? bundleIdentifier : @"";
    if ([phaseName isEqualToString:@"matching"]) {
        log_user("[SBR] matching total=%lu\n", (unsigned long)completed);
        fflush(stdout);
        return;
    }
    static NSSet<NSString *> *currentItemPhases = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        currentItemPhases = [NSSet setWithArray:@[
            @"preflighting", @"processing", @"applying", @"publishing",
            @"restoring",
        ]];
    });
    NSUInteger displayed = completed;
    if (target.length > 0 && completed < total &&
        [currentItemPhases containsObject:phaseName]) {
        displayed++;
    }
    if (total > 0) {
        log_user("[SBR] %s %lu/%lu%s%s\n",
                 phaseName.UTF8String ?: "working",
                 (unsigned long)displayed,
                 (unsigned long)total,
                 target.length > 0 ? " " : "",
                 target.UTF8String ?: "");
    } else {
        log_user("[SBR] %s%s%s\n",
                 phaseName.UTF8String ?: "working",
                 target.length > 0 ? " " : "",
                 target.UTF8String ?: "");
    }
    fflush(stdout);
}

bool settings_apply_snowboardlite_from_defaults_locked(NSUserDefaults *d)
{
    (void)d;
    return [settings_apply_snowboard_remix()[@"ok"] boolValue];
}

bool settings_reapply_snowboardlite_from_defaults_locked(NSUserDefaults *d)
{
    return settings_apply_snowboardlite_from_defaults_locked(d);
}

bool settings_apply_snowboardlite_bundles_from_defaults_locked(NSUserDefaults *d,
                                                               NSSet<NSString *> *bundleIDs)
{
    // Permanent transactions are never triggered implicitly by an install or
    // update notification. An updated app is handled only by an explicit Apply.
    (void)d;
    (void)bundleIDs;
    return false;
}

NSDictionary<NSString *, id> *settings_apply_snowboard_remix(void)
{
    return [CNDSnowBoardRemix applySelectedThemeWithProgress:
        ^(NSString *phase, NSUInteger completed, NSUInteger total,
          NSString *bundleIdentifier) {
            settings_sbl_log_remix_progress(
                phase, completed, total, bundleIdentifier);
        }
        cancellation:nil];
}

NSDictionary<NSString *, id> *settings_update_repair_snowboard_remix(void)
{
    return [CNDSnowBoardRemix
        repairInstalledApplicationUpdatesWithProgress:
            ^(NSString *phase, NSUInteger completed, NSUInteger total,
              NSString *bundleIdentifier) {
                settings_sbl_log_remix_progress(
                    phase, completed, total, bundleIdentifier);
            }
        cancellation:nil];
}

NSDictionary<NSString *, id> *settings_restore_all_snowboard_remix(void)
{
    return [CNDSnowBoardRemix restoreAllWithProgress:
        ^(NSString *phase, NSUInteger completed, NSUInteger total,
          NSString *bundleIdentifier) {
            settings_sbl_log_remix_progress(
                phase, completed, total, bundleIdentifier);
        }
        cancellation:nil];
}

NSDictionary<NSString *, id> *settings_restore_snowboard_remix_bundle(
    NSString *bundleIdentifier)
{
    settings_sbl_log_remix_progress(@"restoring", 0, 1, bundleIdentifier);
    NSDictionary<NSString *, id> *result =
        [CNDSnowBoardRemix restoreBundleIdentifier:bundleIdentifier];
    settings_sbl_log_remix_progress(
        [result[@"ok"] boolValue] ? @"restored" : @"restore-failed",
        1, 1, bundleIdentifier);
    return result;
}

NSDictionary<NSString *, id> *settings_scan_snowboard_remix(void)
{
    return [CNDSnowBoardRemix scanInstalledApplications];
}

NSArray<NSDictionary<NSString *, id> *> *settings_snowboard_remix_statuses(void)
{
    return [CNDSnowBoardRemix applicationStatuses];
}

NSArray<NSDictionary<NSString *, id> *> *settings_snowboard_remix_cached_statuses(void)
{
    return [CNDSnowBoardRemix cachedApplicationStatuses];
}

void settings_refresh_snowboard_remix_statuses_async(void)
{
    [CNDSnowBoardRemix
        refreshApplicationStatusesInBackgroundWithCompletion:nil];
}

void settings_invalidate_snowboard_remix_status_cache(void)
{
    [CNDSnowBoardRemix invalidateCachedApplicationStatuses];
}

static NSArray<NSString *> *settings_sbl_app_bundle_roots(void)
{
    return @[
        @"/var/containers/Bundle/Application",
        @"/private/var/containers/Bundle/Application",
    ];
}

static NSString *settings_sbl_snapshot_value_for_info(NSDictionary *info,
                                                      NSString *bundlePath)
{
    NSString *shortVersion = [info[@"CFBundleShortVersionString"] isKindOfClass:NSString.class]
        ? info[@"CFBundleShortVersionString"] : @"";
    NSString *build = [info[@"CFBundleVersion"] isKindOfClass:NSString.class]
        ? info[@"CFBundleVersion"] : @"";
    NSDictionary<NSFileAttributeKey, id> *attrs =
        [NSFileManager.defaultManager attributesOfItemAtPath:bundlePath error:nil];
    NSDate *mod = [attrs[NSFileModificationDate] isKindOfClass:NSDate.class]
        ? attrs[NSFileModificationDate] : nil;
    unsigned long long modStamp = mod ? (unsigned long long)mod.timeIntervalSince1970 : 0;
    return [NSString stringWithFormat:@"%@|%@|%llu|%@",
            shortVersion ?: @"",
            build ?: @"",
            modStamp,
            bundlePath.lastPathComponent ?: @""];
}

NSDictionary<NSString *, NSString *> *settings_snowboardlite_installed_app_snapshot(void)
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSMutableDictionary<NSString *, NSString *> *snapshot =
        [NSMutableDictionary dictionary];

    for (NSString *root in settings_sbl_app_bundle_roots()) {
        NSArray<NSString *> *uuidDirs = [fm contentsOfDirectoryAtPath:root error:nil];
        for (NSString *uuidDir in uuidDirs) {
            NSString *uuidPath = [root stringByAppendingPathComponent:uuidDir];
            BOOL isDir = NO;
            if (![fm fileExistsAtPath:uuidPath isDirectory:&isDir] || !isDir) continue;

            NSArray<NSString *> *children = [fm contentsOfDirectoryAtPath:uuidPath error:nil];
            for (NSString *child in children) {
                if (![child.pathExtension.lowercaseString isEqualToString:@"app"]) continue;
                NSString *bundlePath = [uuidPath stringByAppendingPathComponent:child];
                NSString *infoPath = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
                NSString *bundleID = [info[@"CFBundleIdentifier"] isKindOfClass:NSString.class]
                    ? info[@"CFBundleIdentifier"] : @"";
                if (bundleID.length == 0 || snapshot[bundleID]) continue;
                snapshot[bundleID] = settings_sbl_snapshot_value_for_info(info, bundlePath);
            }
        }
    }

    return snapshot;
}
