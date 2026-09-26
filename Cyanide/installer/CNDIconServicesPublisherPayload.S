#include "CNDIconServicesPublisherPayload.h"

.section __TEXT,__cndpub,regular,pure_instructions
.p2align 2

.globl _cnd_icon_publisher_payload_probe
_cnd_icon_publisher_payload_probe:
    bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x0, _cnd_icon_publisher_payload_context
    bl _cnd_icon_publisher_payload_probe_body
    ldp x29, x30, [sp], #16
    ret

.globl _cnd_icon_publisher_payload_prepare_descriptor
_cnd_icon_publisher_payload_prepare_descriptor:
    bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x0, _cnd_icon_publisher_payload_context
    bl _cnd_icon_publisher_payload_prepare_descriptor_body
    ldp x29, x30, [sp], #16
    ret

.globl _cnd_icon_publisher_payload_install
_cnd_icon_publisher_payload_install:
    bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x2, _cnd_icon_publisher_payload_context
    bl _cnd_icon_publisher_payload_install_body
    ldp x29, x30, [sp], #16
    ret

.globl _cnd_icon_publisher_payload_generate
_cnd_icon_publisher_payload_generate:
    bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x3, _cnd_icon_publisher_payload_context
    bl _cnd_icon_publisher_payload_generate_body
    ldp x29, x30, [sp], #16
    ret

.globl _cnd_icon_publisher_payload_trigger
_cnd_icon_publisher_payload_trigger:
    bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x0, _cnd_icon_publisher_payload_context
    bl _cnd_icon_publisher_payload_trigger_body
    ldp x29, x30, [sp], #16
    ret

.globl _cnd_icon_publisher_payload_execute
_cnd_icon_publisher_payload_execute:
    bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x0, _cnd_icon_publisher_payload_generate
    adr x1, _cnd_icon_publisher_payload_context
    bl _cnd_icon_publisher_payload_execute_body
    ldp x29, x30, [sp], #16
    ret

.globl _cnd_icon_publisher_payload_cleanup
_cnd_icon_publisher_payload_cleanup:
    bti c
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    adr x0, _cnd_icon_publisher_payload_context
    bl _cnd_icon_publisher_payload_cleanup_body
    ldp x29, x30, [sp], #16
    ret

// iOS arm64/arm64e uses 16 KiB VM pages. Keep the mutable publisher context
// on its own page so the copied function bodies can be RX while counters and
// retained-object addresses remain RW (and non-executable). The publisher
// also validates this offset against the target's runtime page size.
.p2align 14
.globl _cnd_icon_publisher_payload_context
_cnd_icon_publisher_payload_context:
    .space CND_ICON_PUBLISHER_PAYLOAD_CONTEXT_CAPACITY
