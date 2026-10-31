# MAC-label borrow: VM-only, refused on the phone (23A341 / iPhone17,2)

Status: **observed on device, twice, on two independent probes.** Not a proof
about the entitlement gate itself — it is a proof about the transport.

## What was attempted

The IOUserEthernet kernel-call route needs `IOServiceOpen` of
`IOUserEthernetResource` to succeed. That open is gated on
`com.apple.networking.ethernet.user-access`, checked in
`com.apple.iokit.IOUserEthernet`:

```
IOUserEthernetResourceUserClient::initWithTask(task, securityID, type, properties)
    [kext __TEXT_EXEC, static 0xfffffff00ac787b4]
      blraa  super::initWithTask
      add    x23, "com.apple.networking.ethernet.user-access"
                     [kext __TEXT, static 0xfffffff007966f36]
      bl     IOTaskHasEntitlement(task, entitlement)
      cbz    w0 -> "IOUE_UC:: %s entitlement missing"
                     [static 0xfffffff007966f60] and fail
```

The check runs against the *opening task*, at user-client creation. So the
route borrows a donor process's MAC label into the app's own `ucred` for the
duration of the open, then restores it.

## What happens on the phone

Both in-app probes (`CNDPhysicalIOUserEthernetSignerProbe`,
`CNDPhysicalKCall1Probe`) fail at the same instruction-equivalent step: the
write of the donor label image into the app's label object.

From `CNDPhysicalKCall1Probe.json` (2026-10-17, build 1.6 / 1005002, installed
as `com.zeroxjf.ios-cyanide1`):

| field | value |
| --- | --- |
| `result` | `refused-label-borrow` |
| `labelWriteAccepted` | `false` |
| `labelWriteErrno` | `14` (EFAULT) |
| `borrowInstalled` | `false` |
| `borrowRestored` | `true` |
| `labelBytesBeforeWrite` | byte-identical to `labelBytesAfterWrite` |
| `labelChangedAfterWrite` | `false` |

Everything upstream of the write verified good on the same run: KRW ready and
validated, container base matched (`0xfffffff03d1f8000 - 0x00000000361f4000 =
0xfffffff007004000`), header `0xfeedfacf` / filetype `12` (MH_FILESET), self
task resolved, both labels resolved, and the `0x8` / `0x10` policy-slot offsets
confirmed by the app's own `amfi_cslot_get` / `label_get_sandbox` agreement.

The same refusal was recorded earlier by the CS allow-invalid probe
(`scripts/lab/cnd_physical_cs_allow_invalid_probe.m:1976-1978`): "the physical
socket writer returned EFAULT for the protected MAC-label object".

## Interpretation

* The label object is **readable** through the app's socket KRW (all reads on
  the same object succeed) and **not writable** through it (EFAULT, contents
  unchanged).
* The `VM_MIN/MAX_KERNEL_ADDRESS` override in `kexploit_opa334.m:3137-3138` is
  VM-only; the writer's own range gate is not the cause here (it admits the
  object).
* So the borrow transport the signer path used is **VM-only**. Its "VM-proved"
  status was never transferable to the phone, and the chain that depends on it
  never starts on this build/device.
* This is a statement about write access to that object, **not** a statement
  that the entitlement gate can be bypassed some other way.

## Consequence for the route

The phone path needs either a different write transport for the label object, a
different object than the MAC label (e.g. swapping the label pointer in
`ucred` rather than its contents), running the open inside an already-entitled
process, or no borrow at all. See
`docs/research/kcall1-phone-derivation-20261016/README.md` for the route table.
