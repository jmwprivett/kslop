#!/bin/zsh
# cnd_vphone_add_known_host.sh — verify a vPhone guest's SSH host key
# against the pinned fingerprint, then (and only then) add it to the
# known_hosts file. Never blind-trusts an answering host.
#
# Usage: scripts/lab/cnd_vphone_add_known_host.sh <guest-ip> [port=22222]
#
# Exit codes: 0 added; 1 verification failed or already known.

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    print -u2 "usage: $0 <guest-ip> [port=22222]"
    exit 1
fi

IP="$1"
PORT="${2:-22222}"
KNOWN_HOSTS="${HOME}/Library/CyanideVPhoneLab/evidence/phase6/ssh_known_hosts"
PINNED="SHA256:WGFlxCgTIy0TNBJYooUcFrV92cov+ISQ=="

if [[ -f "$KNOWN_HOSTS" ]] && grep -qF "[$IP]:$PORT" "$KNOWN_HOSTS"; then
    print "already known: [$IP]:$PORT in $KNOWN_HOSTS"
    exit 0
fi

KEY="$(ssh-keyscan -p "$PORT" -T 5 -t ecdsa "$IP" 2>/dev/null)" || true
if [[ -z "$KEY" ]]; then
    print -u2 "FAILED: no ECDSA key answered on $IP:$PORT (guest up? SSH booted?)"
    exit 1
fi

FP="$(ssh-keygen -lf - <<<"$KEY" | awk '{print $2}')"
if [[ "$FP" != "$PINNED" ]]; then
    print -u2 "FAILED: fingerprint mismatch"
    print -u2 "  observed: $FP"
    print -u2 "  pinned:   $PINNED"
    print -u2 "Refusing to add. Only remove/replace a changed key for a REBUILT"
    print -u2 "VM after independently proving it is the intended guest."
    exit 1
fi

mkdir -p "$(dirname "$KNOWN_HOSTS")"
echo "$KEY" >> "$KNOWN_HOSTS"
print "added [$IP]:$PORT (verified $FP)"