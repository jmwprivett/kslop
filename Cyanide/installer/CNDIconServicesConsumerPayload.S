#include "CNDIconServicesConsumerPayload.h"

.section __TEXT,__cndhook,regular,pure_instructions
.p2align 2

.globl _cnd_icon_consumer_payload_bootstrap
_cnd_icon_consumer_payload_bootstrap:
    bti c
    adr x0, _cnd_icon_consumer_payload_context
    b _cnd_icon_consumer_payload_bootstrap_body

.globl _cnd_icon_consumer_payload_installer
_cnd_icon_consumer_payload_installer:
    bti c
    b _cnd_icon_consumer_payload_installer_body

.globl _cnd_icon_consumer_payload_probe
_cnd_icon_consumer_payload_probe:
    bti c
    adr x0, _cnd_icon_consumer_payload_context
    b _cnd_icon_consumer_payload_probe_body

.globl _cnd_icon_consumer_payload_install_method
_cnd_icon_consumer_payload_install_method:
    bti c
    adr x2, _cnd_icon_consumer_payload_context
    b _cnd_icon_consumer_payload_install_method_body

.globl _cnd_icon_consumer_payload_init_serialized
_cnd_icon_consumer_payload_init_serialized:
    bti c
    adr x5, _cnd_icon_consumer_payload_context
    b _cnd_icon_consumer_payload_init_serialized_body

.globl _cnd_icon_consumer_payload_init_data
_cnd_icon_consumer_payload_init_data:
    bti c
    adr x4, _cnd_icon_consumer_payload_context
    b _cnd_icon_consumer_payload_init_data_body

.globl _cnd_icon_consumer_payload_init_finalized
_cnd_icon_consumer_payload_init_finalized:
    bti c
    adr x3, _cnd_icon_consumer_payload_context
    b _cnd_icon_consumer_payload_init_finalized_body

.globl _cnd_icon_consumer_payload_layout
_cnd_icon_consumer_payload_layout:
    bti c
    adr x2, _cnd_icon_consumer_payload_context
    b _cnd_icon_consumer_payload_layout_body

/* Keep mutable installer state on a separate VM page from executable code. */
.p2align 14
.globl _cnd_icon_consumer_payload_context
_cnd_icon_consumer_payload_context:
    .space CND_ICON_CONSUMER_PAYLOAD_CONTEXT_CAPACITY
