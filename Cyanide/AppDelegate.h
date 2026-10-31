//
//  AppDelegate.h
//  Cyanide
//
//  Created by seo on 3/24/26.
//

#import <UIKit/UIKit.h>

/// Delivers a host-driven probe command to the already-running app process.
/// Use the registered URL scheme instead of CoreDevice app-container transfer:
/// opening the app-data file service can terminate the process that owns KRW.
BOOL CNDHandleCommandURL(NSURL *url, const char *source);

@interface AppDelegate : UIResponder <UIApplicationDelegate>


@end

