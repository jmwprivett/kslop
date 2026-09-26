//
//  sbcustomizer.h
//  Native port of lightsaber's sbcustomizer dock+grid+labels patch.
//

#ifndef sbcustomizer_h
#define sbcustomizer_h

#import <stdbool.h>
#import <Foundation/Foundation.h>

// orderedDockBundleIDs is an ordered, duplicate-free list of applications to
// append to the dock.  Dock moves are only attempted when dockIcons >= 5.
// Moves are committed to SpringBoard's icon-state store before this function
// returns; the RemoteCall session does not own a rollback transaction.
bool sbcustomizer_apply_in_session(int dockIcons, int hsCols, int hsRows,
                                   bool hideLabels,
                                   NSArray<NSString *> *orderedDockBundleIDs);

// Release any transient state left by an interrupted apply.  Successful
// applies have already committed and released all state, so this never undoes
// a durable dock move.
bool sbcustomizer_stop_in_session(void);

// Drop local bookkeeping without messaging SpringBoard.  This is only for a
// dead/restarted RemoteCall target, where the saved remote pointers are stale.
void sbcustomizer_forget_session_state(void);

// True only while an apply is holding transient remote objects/assertions.
bool sbcustomizer_has_remote_state(void);

#endif
