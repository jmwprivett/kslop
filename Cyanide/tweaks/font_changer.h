//
//  font_changer.h
//  Cyanide
//

#ifndef font_changer_h
#define font_changer_h

#import <Foundation/Foundation.h>
#include <stdbool.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString * const CNDFontChangerRoleRegular;
extern NSString * const CNDFontChangerRoleItalic;
extern NSString * const CNDFontChangerRoleMono;

NSArray<NSString *> *font_changer_all_roles(void);
NSString *font_changer_role_display_name(NSString *role);
NSString *font_changer_role_target_path(NSString *role);
BOOL font_changer_target_exists(NSString *role);

BOOL font_changer_import_font(NSURL *url, NSString *role, NSError **error);
void font_changer_clear_selected_family(void);
BOOL font_changer_has_regular_font(void);
BOOL font_changer_has_any_selected_font(void);
NSString *font_changer_selected_family_summary(void);
NSString *font_changer_role_summary(NSString *role);

bool font_changer_apply_selected_family(void);
bool font_changer_restore_originals(void);

// Recovery bridge for app bundles changed by builds that exposed the retired
// per-app experiment. It never applies a new override.
BOOL font_changer_has_legacy_app_backups(void);
bool font_changer_restore_legacy_app_backups(void);

// Compatibility declarations for the retired per-app font experiment. These
// remain temporarily so older callers can link and users with existing app
// backups can restore them. New code must use the global family APIs above.
#define CND_FONT_CHANGER_APP_API_DEPRECATED(message) __attribute__((deprecated(message)))

NSArray<NSDictionary<NSString *, NSString *> *> *font_changer_installed_apps(void)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Per-app font overrides are retired.");
void font_changer_select_app(NSString *bundleID, NSString *name, NSString *bundlePath)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Per-app font overrides are retired.");
NSString *font_changer_selected_app_summary(void)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Per-app font overrides are retired.");
NSString *font_changer_app_override_summary(void)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Per-app font overrides are retired; this reports legacy recovery state only.");
bool font_changer_diagnose_selected_app(void)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Per-app font overrides are retired.");
bool font_changer_whitelist_selected_app_fonts(void)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Per-app font overrides are retired.");
void font_changer_clear_selected_app_override(void)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Per-app font overrides are retired; preserve legacy state until backups are restored.");
bool font_changer_apply_app_overrides(void)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Per-app font overrides are retired and can no longer be applied.");
bool font_changer_restore_app_overrides(void)
    CND_FONT_CHANGER_APP_API_DEPRECATED("Use font_changer_restore_legacy_app_backups for recovery.");

#undef CND_FONT_CHANGER_APP_API_DEPRECATED

NS_ASSUME_NONNULL_END

#endif /* font_changer_h */
