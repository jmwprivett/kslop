#!/usr/bin/env bash
# Launch the Cyanide iOS research VM visibly with its SSH and kernel-debug
# endpoints enabled. Keep this process running for the lifetime of the VM.

set -euo pipefail

VPHONE_CLI_ROOT="${CND_VPHONE_CLI_ROOT:-$HOME/dev/vphone-cli-1.0.13}"
VM_LIBRARY_ROOT="${CND_VPHONE_VM_LIBRARY_ROOT:-$HOME/Library/CyanideVPhoneLab/VMs}"
VM_NAME="${CND_VPHONE_VM_NAME:-cyanide-ios26-base}"
KERNEL_DEBUG_PORT="${CND_VPHONE_KERNEL_DEBUG_PORT:-62139}"
VPHONE_CLI="$VPHONE_CLI_ROOT/.build/vphone-cli.app/Contents/MacOS/vphone-cli"

usage() {
    cat <<'EOF'
Usage: ./scripts/run-vm.sh

Launches the Cyanide research VM visibly. Keep the terminal open while using
the VM. The guest SSH service uses port 22222 and the local kernel debugger
uses port 62139 by default.

Optional environment overrides:
  CND_VPHONE_CLI_ROOT           vphone-cli checkout
  CND_VPHONE_VM_LIBRARY_ROOT    VM library directory
  CND_VPHONE_VM_NAME            VM name
  CND_VPHONE_KERNEL_DEBUG_PORT  local kernel-debug port
EOF
}

fail() {
    echo "error: $*" >&2
    exit 1
}

if [ "$#" -gt 0 ]; then
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            fail "unknown argument: $1"
            ;;
    esac
fi

[ -x "$VPHONE_CLI" ] \
    || fail "vphone-cli executable not found: $VPHONE_CLI (set CND_VPHONE_CLI_ROOT)"
[ -d "$VM_LIBRARY_ROOT/$VM_NAME" ] \
    || fail "VM not found: $VM_LIBRARY_ROOT/$VM_NAME"
case "$KERNEL_DEBUG_PORT" in
    ''|*[!0-9]*) fail "kernel-debug port must be numeric: $KERNEL_DEBUG_PORT" ;;
esac
[ "$KERNEL_DEBUG_PORT" -ge 1 ] && [ "$KERNEL_DEBUG_PORT" -le 65535 ] \
    || fail "kernel-debug port is outside 1-65535: $KERNEL_DEBUG_PORT"

echo "==> launching $VM_NAME visibly"
echo "==> SSH port: 22222; kernel-debug port: $KERNEL_DEBUG_PORT"
echo "==> keep this terminal open; press Ctrl-C to stop the launcher"

exec "$VPHONE_CLI" vm launch \
    --library-root "$VM_LIBRARY_ROOT" \
    "$VM_NAME" \
    --variant jb \
    --kernel-debug-port "$KERNEL_DEBUG_PORT" \
    --project-root "$VPHONE_CLI_ROOT"
