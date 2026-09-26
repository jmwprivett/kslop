//
//  sb_walk.m
//  Lifted verbatim from darksword_layout.m's rc_collect_list_views /
//  rc_collect_from_windows so themer.m and any future tweak can share them
//  without duplicating the BFS.
//

#import "sb_walk.h"
#import "remote_objc.h"
#import <stdio.h>

static uint64_t sw_sane_count(uint64_t raw, uint64_t cap, const char *label)
{
    // A bad off-main ObjC read can occasionally hand us a pointer-ish value
    // instead of an NSArray count. Treat that as zero; capping it would still
    // drive objectAtIndex: calls into a bogus collection and can crash SB.
    enum { MAX_REASONABLE_COUNT = 4096 };
    static int badCountLogs = 0;
    if (raw > MAX_REASONABLE_COUNT) {
        if (badCountLogs < 8) {
            printf("[SBWALK] ignoring implausible %s count=%llu\n",
                   label ? label : "collection", (unsigned long long)raw);
            badCountLogs++;
        }
        return 0;
    }
    return raw > cap ? cap : raw;
}

static uint64_t sw_safe_msg(uint64_t obj, const char *selname,
                            uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
    if (!r_is_objc_ptr(obj) || !selname ||
        !remote_call_current_success() ||
        !r_responds_main(obj, selname)) {
        return 0;
    }
    return r_msg2_main(obj, selname, a, b, c, d);
}

int sb_collect_views(uint64_t root, uint64_t klass, uint64_t *out, int cap)
{
    if (!r_is_objc_ptr(root) || !r_is_objc_ptr(klass) || !out || cap <= 0 ||
        !remote_call_current_success()) return 0;
    uint64_t selSub  = r_sel("subviews");
    uint64_t selCnt  = r_sel("count");
    uint64_t selObj  = r_sel("objectAtIndex:");
    uint64_t selKind = r_sel("isKindOfClass:");
    if (!selSub || !selCnt || !selObj || !selKind) return 0;

    enum { QMAX = 4096 };
    static uint64_t q[QMAX];
    int head = 0, tail = 0, found = 0, visited = 0;
    q[tail++] = root;

    while (head < tail && visited < QMAX && remote_call_current_success()) {
        uint64_t v = q[head++];
        visited++;
        if (!v) continue;
        if (r_msg_main(v, selKind, klass, 0, 0, 0)) {
            if (found < cap) out[found++] = v;
            continue;
        }
        uint64_t subs = r_msg_main(v, selSub, 0, 0, 0, 0);
        if (!r_is_objc_ptr(subs)) continue;
        uint64_t cn = sw_sane_count(r_msg_main(subs, selCnt, 0, 0, 0, 0),
                                    256, "subviews");
        for (uint64_t i = 0;
             i < cn && tail < QMAX && remote_call_current_success();
            i++) {
            uint64_t c = r_msg_main(subs, selObj, i, 0, 0, 0);
            if (r_is_objc_ptr(c)) q[tail++] = c;
        }
    }
    return found;
}

int sb_collect_views_in_windows(uint64_t klass, uint64_t *out, int cap)
{
    if (!r_is_objc_ptr(klass) || !out || cap <= 0 ||
        !remote_call_current_success()) return 0;
    uint64_t clsApp = r_class("UIApplication");
    if (!clsApp) return 0;
    uint64_t app = sw_safe_msg(clsApp, "sharedApplication", 0, 0, 0, 0);
    if (!app) return 0;

    int n = 0;
    uint64_t wins = sw_safe_msg(app, "windows", 0, 0, 0, 0);
    if (r_is_objc_ptr(wins)) {
        uint64_t wc = sw_sane_count(r_msg2_main(wins, "count", 0, 0, 0, 0),
                                    32, "windows");
        for (uint64_t i = 0;
             i < wc && n < cap && remote_call_current_success();
             i++) {
            uint64_t w = r_msg2_main(wins, "objectAtIndex:", i, 0, 0, 0);
            if (r_is_objc_ptr(w)) {
                n += sb_collect_views(w, klass, out + n, cap - n);
            }
        }
    }
    if (n == 0 && remote_call_current_success()) {
        uint64_t kw = sw_safe_msg(app, "keyWindow", 0, 0, 0, 0);
        if (r_is_objc_ptr(kw)) {
            n += sb_collect_views(kw, klass, out + n, cap - n);
        }
    }
    return n;
}
