//
//  Thread.h
//  Cyanide
//
//  Created by seo on 4/4/26.
//

#import <stdbool.h>
#import <stdint.h>

#import "RemoteCall.h"

bool inject_guard_exception(uint64_t thread, uint64_t code);
void clear_guard_exception(uint64_t thread);
bool thread_get_state_wrapper(mach_port_t machThread, arm_thread_state64_internal *outState);
bool thread_set_state_wrapper(mach_port_t machThread, uint64_t threadAddr, arm_thread_state64_internal *state);
/* Re-sign raw PC/LR values from the caller's PAC context into the context of
 * an exact target thread control port using XNU's public state converter.
 * This path performs no kernel call and does not install or execute state. */
bool thread_convert_sign_state_for_target(mach_port_t targetThread,
                                          arm_thread_state64_internal *state,
                                          uint64_t pc, uint64_t lr);
bool thread_resume_wrapper(mach_port_t machThread);
void thread_set_pac_keys(uint64_t threadAddr, uint64_t keyA, uint64_t keyB);
