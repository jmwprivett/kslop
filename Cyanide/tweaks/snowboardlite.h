//
//  snowboardlite.h
//  Cyanide
//  Adapted from https://github.com/d1y/cyanide-ios (AGPL-3.0).
//

#ifndef snowboardlite_h
#define snowboardlite_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#include <stdbool.h>

extern NSString * const kSnowBoardLiteThemeBuiltinIOS6;
extern NSString * const kSettingsSnowBoardRemixDebugThreeAppLimit;
extern NSString * const kSettingsSnowBoardRemixInstallConsumerMappings;

NSArray<NSDictionary *> *settings_sbl_load_manifest(void);
BOOL settings_sbl_save_manifest(NSArray<NSDictionary *> *themes);
NSDictionary *settings_sbl_selected_theme(void);
BOOL settings_sbl_selected_builtin_ios6(void);
NSString *settings_sbl_resolved_icons_path_for_theme(NSDictionary *theme);
NSArray<UIImage *> *settings_sbl_preview_images_for_theme(NSDictionary *theme,
                                                          BOOL builtIn,
                                                          NSUInteger limit);
BOOL settings_sbl_import_folder_theme_named(NSURL *url,
                                            NSString *displayName,
                                            NSString *sourceType,
                                            NSError **error);
BOOL settings_sbl_import_folder_theme(NSURL *url, NSError **error);
NSDictionary<NSString *, NSData *> *settings_sbl_selected_theme_data(void);
NSDictionary<NSString *, id> *settings_apply_snowboard_remix(void);
NSDictionary<NSString *, id> *settings_update_repair_snowboard_remix(void);
NSDictionary<NSString *, id> *settings_restore_all_snowboard_remix(void);
NSDictionary<NSString *, id> *settings_restore_snowboard_remix_bundle(NSString *bundleIdentifier);
NSDictionary<NSString *, id> *settings_scan_snowboard_remix(void);
NSArray<NSDictionary<NSString *, id> *> *settings_snowboard_remix_statuses(void);
NSArray<NSDictionary<NSString *, id> *> *settings_snowboard_remix_cached_statuses(void);
void settings_refresh_snowboard_remix_statuses_async(void);
void settings_invalidate_snowboard_remix_status_cache(void);
bool settings_apply_snowboardlite_from_defaults_locked(NSUserDefaults *d);
bool settings_reapply_snowboardlite_from_defaults_locked(NSUserDefaults *d);
bool settings_apply_snowboardlite_bundles_from_defaults_locked(NSUserDefaults *d,
                                                               NSSet<NSString *> *bundleIDs);

NSDictionary<NSString *, NSString *> *settings_snowboardlite_installed_app_snapshot(void);

BOOL settings_snowboardlite_has_selected_theme(void);
NSString *settings_snowboardlite_selected_theme_display_name(void);

#endif /* snowboardlite_h */
