//
//  sb_walk.h
//  RemoteCall view-tree helpers shared between tweaks that need to find
//  SpringBoard views of a particular class (SBIconListView, SBIconView, etc).
//

#ifndef sb_walk_h
#define sb_walk_h

#import <stdint.h>

// BFS from `root` collecting subviews that are instances of `klass`.
// UIKit snapshots are taken synchronously on SpringBoard's main thread.
// Matched views are NOT recursed into. Returns the count written to `out`,
// capped at `cap`. Not reentrant — uses a static BFS queue.
int sb_collect_views(uint64_t root, uint64_t klass, uint64_t *out, int cap);

// Walks every UIApplication window (falls back to keyWindow if -windows
// returns empty) and collects views of `klass` across all of them.
int sb_collect_views_in_windows(uint64_t klass, uint64_t *out, int cap);

#endif /* sb_walk_h */
