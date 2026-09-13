#!/bin/sh
#
# install-agent.sh — install or upgrade the ServerOS agent.
#
# Run as root, over SSH, by the ServerOS Mac app during "Add Server". Also
# perfectly runnable by hand, which is the point of it being a real script
# rather than a string inside the app:
#
#     sudo sh install-agent.sh --binary ./serveros-agent --profile hardened
#
# The agent has to come from somewhere: either --binary (a file already on this
# machine — what ServerOS passes, having copied it over SSH) or --base-url (a
# host you control). There is no default download host; see BASE_URL below.
#
# CONTRACT WITH THE CALLER
#
#   * stdout carries exactly one line, at the very end:
#
#         SERVEROS-INSTALL-OK <version> <arch> <init-system>
#
#     Everything else — progress, warnings, errors — goes to stderr. The app
#     parses that line; anything else on stdout is a bug.
#
#   * Exit 0 means installed. Any other exit means nothing was started, and
#     stderr says why.
#
#   * It is idempotent. Running it again upgrades in place and leaves the
#     server's identity (/etc/serveros/agent.key) alone. Enrollment is a
#     separate, explicit step — this script never mints or replaces a secret.
#
#   * It does not start the agent when --no-start is given, because the app
#     enrolls between installing and starting: the agent reads its key once, at
#     startup, and starting it before there is a key just makes it exit.
#
# POSIX sh only: /bin/sh is dash on Debian and busybox on Alpine, and neither
# has arrays, `local`, or [[ ]].

set -eu

VERSION="latest"
# No default download host, deliberately. There is no public one, and a default
# that points at a host which does not resolve turns "you didn't tell me where
# to get the agent" into "your server can't reach the internet" — which is a
# different problem, in a different place, and sends whoever is debugging it
# somewhere the fault cannot be. Either pass --binary (what ServerOS does: it
# copies the agent over the SSH connection it already holds) or pass a
# --base-url you actually control.
BASE_URL=""
PROFILE="hardened"
START=1
ALLOW_UNVERIFIED=0
BINARY=""

PREFIX="/usr/local/lib/serveros"
BINDIR="/usr/local/bin"
CONFIG_DIR="/etc/serveros"
DATA_DIR="/var/lib/serveros"
RUN_DIR="/run/serveros"
LOG_FILE="/var/log/serveros-agent.log"
SERVICE="serveros-agent"
SERVICE_USER="serveros"
UNIT_PATH="/etc/systemd/system/serveros-agent.service"
DROPIN_DIR="/etc/systemd/system/serveros-agent.service.d"
INIT_PATH="/etc/init.d/serveros-agent"
PID_FILE="/run/serveros/agent.pid"

log() { printf '%s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat >&2 <<'USAGE'
Usage: install-agent.sh [options]

  --version <v>        Agent version to install (default: latest)
  --base-url <url>     Where to download it from
  --binary <path>      Install this file instead of downloading
  --profile <p>        hardened (default) or manage — see below
  --no-start           Install and enable, but do not start the service
  --allow-unverified   Install even if no published checksum was found
  -h, --help           This

Profiles:
  hardened  The systemd unit runs with ProtectSystem=strict, ProtectHome=read-only
            and no capabilities. Monitoring, Docker, services and logs all work;
            anything that writes outside the agent's own directories does not.
  manage    Adds a drop-in that relaxes those restrictions so the agent can
            manage users, files and system services. Choose it knowingly.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --base-url) BASE_URL="${2:?--base-url needs a value}"; shift 2 ;;
        --binary) BINARY="${2:?--binary needs a value}"; shift 2 ;;
        --profile) PROFILE="${2:?--profile needs a value}"; shift 2 ;;
        --no-start) START=0; shift ;;
        --allow-unverified) ALLOW_UNVERIFIED=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

case "$PROFILE" in
    hardened|manage) ;;
    *) die "unknown profile: $PROFILE" ;;
esac

# ---------------------------------------------------------------- environment

[ "$(id -u)" = "0" ] || die "this installer must run as root (use sudo)"

case "$(uname -s)" in
    Linux) ;;
    *) die "the ServerOS agent runs on Linux only (this is $(uname -s))" ;;
esac

MACHINE="$(uname -m)"
case "$MACHINE" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) die "no ServerOS agent build for $MACHINE (x86_64 and aarch64 only)" ;;
esac

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    INIT="systemd"
else
    INIT="sysv"
fi

log "ServerOS agent installer: $ARCH, $INIT, profile $PROFILE"

# ------------------------------------------------------------------- the user
#
# A dedicated account so the data directory, the runtime directory and (later,
# when the agent no longer needs root for everything) the process itself belong
# to something other than root. Creating it is best-effort: a server with an
# unusual user database should not fail an install over a group.

ensure_user() {
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        return 0
    fi
    if command -v useradd >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null \
            || useradd --system --no-create-home --shell /sbin/nologin "$SERVICE_USER" 2>/dev/null \
            || useradd --system "$SERVICE_USER" 2>/dev/null \
            || true
    elif command -v adduser >/dev/null 2>&1; then
        # busybox / Alpine
        adduser -S -D -H -s /sbin/nologin "$SERVICE_USER" 2>/dev/null || true
    fi

    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        log "created system user $SERVICE_USER"
    else
        log "warning: could not create the $SERVICE_USER user; directories will be root-owned"
    fi
}

ensure_user

# ------------------------------------------------------------- the directories

install -d -m 0700 "$CONFIG_DIR"
install -d -m 0750 "$DATA_DIR"
install -d -m 0750 "$RUN_DIR"
install -d -m 0755 "$PREFIX"

# root:serveros rather than serveros:serveros — the agent runs as root today,
# and a directory it does not own is a directory it cannot write once
# capabilities are dropped.
if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    chown root:"$SERVICE_USER" "$DATA_DIR" "$RUN_DIR" 2>/dev/null || true
fi

# ---------------------------------------------------------------- the binary

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/serveros-install.XXXXXX")"
cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT INT TERM

DOWNLOAD="$TMP_DIR/serveros-agent"

fetch() {
    # fetch <url> <destination>; returns non-zero if it could not be fetched
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 15 --max-time 600 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout=600 -O "$2" "$1"
    else
        die "neither curl nor wget is installed, so the agent cannot be downloaded"
    fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        echo ""
    fi
}

if [ -n "$BINARY" ]; then
    [ -f "$BINARY" ] || die "no such file: $BINARY"
    cp "$BINARY" "$DOWNLOAD"
    log "installing from $BINARY"
elif [ -z "$BASE_URL" ]; then
    die "no agent to install: pass --binary <path> (ServerOS copies the agent to
the server over SSH and does this for you) or --base-url <url> to download one"
else
    URL="$BASE_URL/$VERSION/serveros-agent-linux-$ARCH"
    log "downloading $URL"
    fetch "$URL" "$DOWNLOAD" || die "could not download the agent from $URL"

    if fetch "$URL.sha256" "$TMP_DIR/sha256" 2>/dev/null; then
        EXPECTED="$(cut -d' ' -f1 < "$TMP_DIR/sha256" | tr -d '\r\n')"
        ACTUAL="$(sha256_of "$DOWNLOAD")"
        if [ -z "$ACTUAL" ]; then
            [ "$ALLOW_UNVERIFIED" = "1" ] \
                || die "no sha256sum on this server, so the download cannot be verified (--allow-unverified to skip)"
            log "warning: cannot verify the download — no sha256sum on this server"
        elif [ "$EXPECTED" != "$ACTUAL" ]; then
            die "the downloaded agent does not match its published checksum — refusing to install"
        else
            log "checksum verified"
        fi
    else
        [ "$ALLOW_UNVERIFIED" = "1" ] \
            || die "no published checksum for $VERSION ($URL.sha256) — refusing to install (--allow-unverified to skip)"
        log "warning: installing without a published checksum"
    fi
fi

chmod 0755 "$DOWNLOAD"
"$DOWNLOAD" version >/dev/null 2>&1 || die "the downloaded file does not run on this server (wrong architecture, or a corrupt download)"

INSTALLED_VERSION="$("$DOWNLOAD" version 2>/dev/null | awk '{print $2}')"
[ -n "$INSTALLED_VERSION" ] || INSTALLED_VERSION="$VERSION"

# Stop a running instance before swapping the file underneath it. The rename
# below is atomic and would not disturb a running process, but an agent holding
# the old binary and the new key is a confusing state to leave a server in — and
# the caller restarts it a moment later anyway.
if [ "$INIT" = "systemd" ] && systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
    log "stopping the running agent"
    systemctl stop "$SERVICE" || true
elif [ -x "$INIT_PATH" ]; then
    "$INIT_PATH" stop >/dev/null 2>&1 || true
fi

install -m 0755 "$DOWNLOAD" "$PREFIX/serveros-agent.new"
mv -f "$PREFIX/serveros-agent.new" "$PREFIX/serveros-agent"
ln -sf "$PREFIX/serveros-agent" "$BINDIR/serveros-agent"
log "installed $PREFIX/serveros-agent ($INSTALLED_VERSION)"

# ----------------------------------------------------------------- the config
#
# Written only if absent: a server that has been tuned by hand keeps its
# settings across upgrades. The agent fills in every default itself, so a
# minimal file is a complete one.

if [ ! -f "$CONFIG_DIR/agent.json" ]; then
    umask 077
    cat > "$CONFIG_DIR/agent.json" <<JSON
{
  "bind": "127.0.0.1",
  "port": 8723,
  "unix_socket": "$RUN_DIR/agent.sock",
  "data_dir": "$DATA_DIR",
  "key_path": "$CONFIG_DIR/agent.key",
  "log_level": "info"
}
JSON
    chmod 0600 "$CONFIG_DIR/agent.json"
    log "wrote $CONFIG_DIR/agent.json"
fi

# ---------------------------------------------------------------- the service

install_systemd() {
    cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=ServerOS agent
Documentation=https://serveros.app/docs/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PREFIX/serveros-agent serve --config $CONFIG_DIR/agent.json
Restart=on-failure
RestartSec=2
TimeoutStopSec=20

RuntimeDirectory=serveros
RuntimeDirectoryMode=0750
StateDirectory=serveros
StateDirectoryMode=0750

# Hardening. The agent is a network-reachable daemon on a machine its owner
# cares about; it gets the smallest box it can still do its job in.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$CONFIG_DIR $DATA_DIR $RUN_DIR
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

# Read-only file access beyond what the agent owns.
#
# The agent runs as root, but with an otherwise-empty capability set — so plain
# discretionary access control applies, and root that holds no capabilities
# cannot read a file it does not own. That is what made ServerOS report
# "Permission denied" when reading a user's 0600 ~/.ssh/authorized_keys, or a
# config in another user's home: every one of those is exactly the kind of file
# a server-management tool is expected to be able to look at.
#
# CAP_DAC_READ_SEARCH is the read-only bypass, and only that: it lets the agent
# READ any file and traverse any directory, and confers no power to write,
# change ownership, or alter anything. It is the smallest capability that makes
# a read-only view of the machine actually work. Writing — creating users,
# changing permissions — is the manage profile, which adds CAP_DAC_OVERRIDE on
# top of this.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
UNIT
    chmod 0644 "$UNIT_PATH"

    rm -f "$DROPIN_DIR/10-manage.conf"
    if [ "$PROFILE" = "manage" ]; then
        install -d -m 0755 "$DROPIN_DIR"
        cat > "$DROPIN_DIR/10-manage.conf" <<'DROPIN'
# Written by install-agent.sh --profile manage.
#
# Managing Linux users, file permissions and system services means writing to
# /etc and /home and changing ownership, none of which the hardened profile
# allows. This drop-in opens exactly that much and no more. Delete this file
# and `systemctl daemon-reload` to go back to read-only management.
[Service]
ProtectSystem=full
ProtectHome=no
ReadWritePaths=/etc /var /run /home /srv /opt
CapabilityBoundingSet=
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_FSETID CAP_KILL CAP_SETGID CAP_SETUID CAP_AUDIT_WRITE
MemoryDenyWriteExecute=no
DROPIN
        chmod 0644 "$DROPIN_DIR/10-manage.conf"
    fi

    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || log "warning: could not enable $SERVICE at boot"
    log "wrote $UNIT_PATH"
}

install_sysv() {
    cat > "$INIT_PATH" <<SYSV
#!/bin/sh
### BEGIN INIT INFO
# Provides:          serveros-agent
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: ServerOS agent
### END INIT INFO
#
# Fallback for servers without systemd. No supervision and no restart-on-crash:
# if this is your server, systemd (or your own supervisor) is better.

BIN="$PREFIX/serveros-agent"
CONFIG="$CONFIG_DIR/agent.json"
PID_FILE="$PID_FILE"
LOG_FILE="$LOG_FILE"

running() {
    [ -f "\$PID_FILE" ] || return 1
    kill -0 "\$(cat "\$PID_FILE")" 2>/dev/null
}

case "\$1" in
    start)
        running && { echo "already running"; exit 0; }
        mkdir -p "$RUN_DIR"
        nohup "\$BIN" serve --config "\$CONFIG" >> "\$LOG_FILE" 2>&1 &
        echo \$! > "\$PID_FILE"
        ;;
    stop)
        running || { echo "not running"; exit 0; }
        kill "\$(cat "\$PID_FILE")" 2>/dev/null || true
        rm -f "\$PID_FILE"
        ;;
    restart)
        "\$0" stop || true
        sleep 1
        "\$0" start
        ;;
    status)
        if running; then echo "active"; exit 0; else echo "inactive"; exit 3; fi
        ;;
    *)
        echo "usage: \$0 {start|stop|restart|status}" >&2
        exit 2
        ;;
esac
SYSV
    chmod 0755 "$INIT_PATH"
    touch "$LOG_FILE" && chmod 0640 "$LOG_FILE"

    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d serveros-agent defaults >/dev/null 2>&1 || true
    elif command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add serveros-agent >/dev/null 2>&1 || true
    elif command -v rc-update >/dev/null 2>&1; then
        rc-update add serveros-agent default >/dev/null 2>&1 || true
    fi
    log "wrote $INIT_PATH"
}

if [ "$INIT" = "systemd" ]; then
    install_systemd
else
    log "systemd not found; installing an init script instead"
    install_sysv
fi

# ------------------------------------------------------------------ starting

if [ "$START" = "1" ]; then
    if [ ! -f "$CONFIG_DIR/agent.key" ]; then
        log "not starting: this server is not enrolled yet (run: serveros-agent enroll)"
    elif [ "$INIT" = "systemd" ]; then
        systemctl restart "$SERVICE" || die "the agent would not start; see: journalctl -u $SERVICE -n 50"
        log "started $SERVICE"
    else
        "$INIT_PATH" restart >/dev/null 2>&1 || die "the agent would not start; see $LOG_FILE"
        log "started $SERVICE"
    fi
else
    log "not starting (--no-start)"
fi

# The one line on stdout. Nothing above this point writes to it.
printf 'SERVEROS-INSTALL-OK %s %s %s\n' "$INSTALLED_VERSION" "$ARCH" "$INIT"
