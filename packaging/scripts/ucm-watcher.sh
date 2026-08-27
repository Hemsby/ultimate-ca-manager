#!/bin/bash
# UCM Service Action Handler
# Triggered by ucm-watcher.path when signal files appear in /opt/ucm/data/
# Handles: restart requests, package updates
# Runs as root via systemd

set -euo pipefail

DATA_DIR="/opt/ucm/data"
RESTART_FILE="$DATA_DIR/.restart_requested"
UPDATE_FILE="$DATA_DIR/.update_pending"
MANIFEST_FILE="$DATA_DIR/.update_manifest.json"
RESULT_FILE="$DATA_DIR/.update_result.json"
LOG_FILE="/var/log/ucm/ucm.log"

log() {
    echo "$(date -Iseconds) [ucm-watcher] $*" | tee -a "$LOG_FILE"
}

manifest_get() {
    # Read one string field from the operation manifest ('' when absent)
    python3 - "$1" <<'PYEOF' 2>/dev/null || true
import json, sys
try:
    with open("/opt/ucm/data/.update_manifest.json") as f:
        print(json.load(f).get(sys.argv[1]) or '')
except Exception:
    pass
PYEOF
}

installed_version() {
    if command -v dpkg-query &>/dev/null; then
        dpkg-query -W -f='${Version}' ucm 2>/dev/null || true
    elif command -v rpm &>/dev/null; then
        rpm -q --qf '%{VERSION}' ucm 2>/dev/null || true
    fi
}

write_result() {
    # write_result <status> <step> <error> — durable, atomic (rename),
    # consumed once by the UCM backend after the restart
    STATUS="$1" STEP="$2" ERROR="$3" INSTALLED="$(installed_version)" \
        python3 - <<'PYEOF' >> "$LOG_FILE" 2>&1 || true
import json, os, time
data_dir = "/opt/ucm/data"
manifest = {}
try:
    with open(os.path.join(data_dir, ".update_manifest.json")) as f:
        manifest = json.load(f)
except Exception:
    pass
result = {
    "op_id": manifest.get("op_id"),
    "from_version": manifest.get("from_version"),
    "to_version": manifest.get("to_version"),
    "initiated_by": manifest.get("initiated_by"),
    "status": os.environ["STATUS"],
    "step": os.environ["STEP"] or None,
    "error": (os.environ["ERROR"] or None) and os.environ["ERROR"][:500],
    "installed_version": os.environ["INSTALLED"] or None,
    "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
tmp = os.path.join(data_dir, ".update_result.json.tmp")
with open(tmp, "w") as f:
    json.dump(result, f)
os.chmod(tmp, 0o644)
os.replace(tmp, os.path.join(data_dir, ".update_result.json"))
PYEOF
    rm -f "$MANIFEST_FILE"
}

finish_update() {
    # Always restart UCM so the backend consumes the result and emits the
    # truthful installed/failed event
    rm -f "$RESTART_FILE"
    log "Update handling done (status recorded), restarting UCM..."
    systemctl restart ucm >> "$LOG_FILE" 2>&1
    exit 0
}

# ── Handle update (install package + verify + record result + restart) ──
if [ -f "$UPDATE_FILE" ]; then
    PACKAGE_PATH=$(cat "$UPDATE_FILE")
    rm -f "$UPDATE_FILE"

    if [ -z "$PACKAGE_PATH" ] || [ ! -f "$PACKAGE_PATH" ]; then
        log "ERROR: Invalid or missing package path: '$PACKAGE_PATH'"
        write_result failed precheck "invalid or missing package path"
        finish_update
    fi

    log "Starting update with package: $PACKAGE_PATH"
    INSTALL_OK=1

    if [[ "$PACKAGE_PATH" == *.deb ]]; then
        log "Installing DEB package..."
        # dpkg first, then apt to resolve any missing dependencies; the
        # authoritative success check is the version verification below
        dpkg -i "$PACKAGE_PATH" >> "$LOG_FILE" 2>&1 || true
        log "Resolving dependencies..."
        if ! apt-get -f install -y >> "$LOG_FILE" 2>&1; then
            log "ERROR: apt-get -f install failed"
            write_result failed apt-get "apt-get -f install failed (see ucm.log)"
            INSTALL_OK=0
        fi
    elif [[ "$PACKAGE_PATH" == *.rpm ]]; then
        log "Installing RPM package..."
        if command -v dnf &>/dev/null; then
            RPM_TOOL=dnf; dnf install -y "$PACKAGE_PATH" >> "$LOG_FILE" 2>&1 || INSTALL_OK=0
        elif command -v yum &>/dev/null; then
            RPM_TOOL=yum; yum localinstall -y "$PACKAGE_PATH" >> "$LOG_FILE" 2>&1 || INSTALL_OK=0
        else
            RPM_TOOL=rpm; rpm -U --force "$PACKAGE_PATH" >> "$LOG_FILE" 2>&1 || INSTALL_OK=0
        fi
        if [ "$INSTALL_OK" != "1" ]; then
            log "ERROR: RPM install failed ($RPM_TOOL)"
            write_result failed "$RPM_TOOL" "RPM install failed (see ucm.log)"
        fi
    else
        log "ERROR: Unknown package format: $PACKAGE_PATH"
        write_result failed precheck "unknown package format"
        INSTALL_OK=0
    fi

    if [ "$INSTALL_OK" = "1" ]; then
        # Verify the package version actually on the system before declaring
        # success — a repaired-but-not-upgraded install must report failed
        TARGET_VERSION="$(manifest_get to_version)"
        DETECTED="$(installed_version)"
        log "Installed package version: '${DETECTED}' (target: '${TARGET_VERSION}')"
        if [ -n "$TARGET_VERSION" ] && [ "${DETECTED%%-*}" != "$TARGET_VERSION" ] && [ "$DETECTED" != "$TARGET_VERSION" ]; then
            log "ERROR: installed version does not match the update target"
            write_result failed verify "installed version '$DETECTED' does not match target '$TARGET_VERSION'"
        else
            log "Package installed and version verified"
            write_result installed "" ""
        fi
    fi

    # Clean up downloaded package
    PACKAGE_DIR=$(dirname "$PACKAGE_PATH")
    if [[ "$PACKAGE_DIR" == */updates ]]; then
        rm -f "$PACKAGE_PATH"
        log "Cleaned up package: $PACKAGE_PATH"
    fi

    finish_update
fi

# ── Handle simple restart ──
if [ -f "$RESTART_FILE" ]; then
    rm -f "$RESTART_FILE"
    log "Restart requested, restarting UCM..."
    systemctl restart ucm >> "$LOG_FILE" 2>&1
    log "Restart complete"
    exit 0
fi

log "Watcher triggered but no action file found"
