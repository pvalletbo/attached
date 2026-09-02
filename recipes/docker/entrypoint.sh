#!/bin/sh
set -eu

fail() {
    printf 'attached-herdr: %s\n' "$*" >&2
    exit 2
}

prepare_secret_file() {
    destination="$1"
    environment_name="$2"
    environment_value="$3"
    source_file="$4"

    if [ -n "$environment_value" ] && [ -n "$source_file" ]; then
        fail "configure either $environment_name or ${environment_name}_FILE, not both"
    fi
    if [ -n "$environment_value" ]; then
        printf '%s' "$environment_value" >"$destination"
    elif [ -n "$source_file" ]; then
        [ -r "$source_file" ] || fail "cannot read secret file $source_file"
        cat "$source_file" >"$destination"
    else
        fail "$environment_name or ${environment_name}_FILE is required"
    fi
    [ -s "$destination" ] || fail "$environment_name is empty"
    chmod 0600 "$destination"
}

# Environment-only secret injection is needed on some platforms. Copy those values
# into owner-only files and re-exec so long-running processes do not inherit them.
if [ "${ATTACHED_ENTRYPOINT_STAGE-}" != "run" ]; then
    unset destination environment_name environment_value source_file
    unset local_password_value local_password_file
    unset publish_bundle_value publish_bundle_file current_uid

    # Keep private shell copies, then scrub exported values before invoking even
    # short-lived helpers such as mkdir, mktemp, cat, chmod, or setpriv.
    local_password_value="${ATTACHED_LOCAL_PASSWORD-}"
    local_password_file="${ATTACHED_LOCAL_PASSWORD_FILE-}"
    publish_bundle_value="${ATTACHED_PUBLISH_BUNDLE-}"
    publish_bundle_file="${ATTACHED_PUBLISH_BUNDLE_FILE-}"
    unset ATTACHED_LOCAL_PASSWORD ATTACHED_LOCAL_PASSWORD_FILE
    unset ATTACHED_PUBLISH_BUNDLE ATTACHED_PUBLISH_BUNDLE_FILE
    current_uid="$(id -u)"

    umask 077
    runtime_root="${ATTACHED_RUNTIME_ROOT:-${TMPDIR:-/tmp}}"
    case "$runtime_root" in
        /*) ;;
        *) fail "ATTACHED_RUNTIME_ROOT must be an absolute path" ;;
    esac
    mkdir -p "$runtime_root"
    runtime_dir="$(mktemp -d "$runtime_root/attached-herdr.XXXXXX")"
    password_input="$runtime_dir/local-password"
    bundle_input="$runtime_dir/publish.bundle"
    trap 'rm -rf "$runtime_dir"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    prepare_secret_file \
        "$password_input" \
        ATTACHED_LOCAL_PASSWORD \
        "$local_password_value" \
        "$local_password_file"
    prepare_secret_file \
        "$bundle_input" \
        ATTACHED_PUBLISH_BUNDLE \
        "$publish_bundle_value" \
        "$publish_bundle_file"

    local_password_value=""
    local_password_file=""
    publish_bundle_value=""
    publish_bundle_file=""
    environment_value=""
    source_file=""
    export ATTACHED_ENTRYPOINT_STAGE=run
    export ATTACHED_RUNTIME_DIR="$runtime_dir"

    init_bin="${ATTACHED_INIT_BIN-}"
    if [ -n "$init_bin" ]; then
        command -v "$init_bin" >/dev/null 2>&1 || fail "init executable not found: $init_bin"
        set -- "$init_bin" -- "$0" "$@"
    else
        set -- "$0" "$@"
    fi

    run_as_uid="${ATTACHED_RUN_AS_UID-}"
    run_as_gid="${ATTACHED_RUN_AS_GID:-$run_as_uid}"
    if [ "$current_uid" -eq 0 ] && [ -n "$run_as_uid" ]; then
        case "$run_as_uid" in
            *[!0-9]*) fail "ATTACHED_RUN_AS_UID must be numeric" ;;
        esac
        case "$run_as_gid" in
            '' | *[!0-9]*) fail "ATTACHED_RUN_AS_GID must be numeric" ;;
        esac
        [ "$run_as_uid" -ne 0 ] || fail "ATTACHED_RUN_AS_UID must not be 0"
        [ "$run_as_gid" -ne 0 ] || fail "ATTACHED_RUN_AS_GID must not be 0"
        command -v setpriv >/dev/null 2>&1 || fail "setpriv is required to drop root privileges"
        chown -R "$run_as_uid:$run_as_gid" "$runtime_dir"
        trap - EXIT HUP INT TERM
        exec setpriv \
            --no-new-privs \
            --reuid="$run_as_uid" \
            --regid="$run_as_gid" \
            --clear-groups \
            "$@"
    fi

    trap - EXIT HUP INT TERM
    exec "$@"
fi

# Never pass externally supplied secret variables to the publisher, including
# when an invalid caller tries to enter the internal stage directly.
unset ATTACHED_LOCAL_PASSWORD ATTACHED_LOCAL_PASSWORD_FILE
unset ATTACHED_PUBLISH_BUNDLE ATTACHED_PUBLISH_BUNDLE_FILE
if [ "$(id -u)" -eq 0 ] && [ -n "${ATTACHED_RUN_AS_UID-}" ]; then
    fail "refusing to launch the publisher before dropping root privileges"
fi

umask 077
runtime_dir="${ATTACHED_RUNTIME_DIR:?missing prepared runtime directory}"
password_input="$runtime_dir/local-password"
bundle_input="$runtime_dir/publish.bundle"
attached_bin="${ATTACHED_BIN:-attached}"
herdr_bin="${HERDR_BIN:-herdr}"
expect_bin="${EXPECT_BIN:-expect}"
expect_script="${ATTACHED_EXPECT_SCRIPT:-/usr/local/libexec/attached-herdr/run-attached.exp}"
state_dir="${ATTACHED_STATE_DIR:-${HOME:-/tmp}/.local/state/attached}"
startup_cwd="${HERDR_STARTUP_CWD:-/workspace}"
health_port="${ATTACHED_HEALTH_PORT:-${PORT:-8080}}"
ready_file="$runtime_dir/health/healthz"
child_pid_file="$runtime_dir/attached-child.pid"
unset ATTACHED_ENTRYPOINT_STAGE ATTACHED_RUNTIME_DIR ATTACHED_RUNTIME_ROOT
unset ATTACHED_INIT_BIN ATTACHED_RUN_AS_UID ATTACHED_RUN_AS_GID

case "$runtime_dir" in
    /*) ;;
    *) fail "prepared runtime directory must be an absolute path" ;;
esac
case "${runtime_dir##*/}" in
    attached-herdr.??????) ;;
    *) fail "prepared runtime directory has an invalid name" ;;
esac
[ -d "$runtime_dir" ] || fail "prepared runtime directory is missing"
trap 'rm -rf "$runtime_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

case "$state_dir" in
    /*) ;;
    *) fail "ATTACHED_STATE_DIR must be an absolute path" ;;
esac
case "$startup_cwd" in
    /*) ;;
    *) fail "HERDR_STARTUP_CWD must be an absolute path" ;;
esac

command -v "$attached_bin" >/dev/null 2>&1 || fail "Attached executable not found: $attached_bin"
command -v "$herdr_bin" >/dev/null 2>&1 || fail "Herdr executable not found: $herdr_bin"
command -v "$expect_bin" >/dev/null 2>&1 || fail "Expect executable not found: $expect_bin"
[ -r "$expect_script" ] || fail "Expect driver not found: $expect_script"
[ -s "$password_input" ] || fail "prepared local password is missing"
[ -s "$bundle_input" ] || fail "prepared publish bundle is missing"

mkdir -p "$state_dir" "$startup_cwd" "$runtime_dir/health" "${HOME:-/tmp}"
chmod 0700 "$state_dir" "$runtime_dir" "$runtime_dir/health"
rm -f "$ready_file" "${ready_file}.tmp" "$child_pid_file" "${child_pid_file}.tmp"

case "$health_port" in
    0) ;;
    *[!0-9]* | '') fail "ATTACHED_HEALTH_PORT must be 0 or an integer from 1 to 65535" ;;
    *)
        [ "$health_port" -le 65535 ] || fail "ATTACHED_HEALTH_PORT must be at most 65535"
        command -v busybox >/dev/null 2>&1 || fail "busybox is required when health checks are enabled"
        ;;
esac

cd "$startup_cwd"

set -- "$attached_bin" serve \
    --herdr-bin "$herdr_bin" \
    --state-dir "$state_dir" \
    --bundle-file "$bundle_input"
if [ -n "${ATTACHED_HOST_LABEL-}" ]; then
    set -- "$@" --host-label "$ATTACHED_HOST_LABEL"
fi

"$expect_bin" "$expect_script" \
    "$password_input" "$bundle_input" "$ready_file" "$child_pid_file" "$@" &
attached_pid=$!

health_pid=""
if [ "$health_port" -ne 0 ]; then
    start_health_when_ready() {
        trap - EXIT HUP INT TERM
        while kill -0 "$attached_pid" 2>/dev/null; do
            if [ -f "$ready_file" ]; then
                exec env -i PATH="${PATH:-/usr/bin:/bin}" \
                    busybox httpd -f -p "0.0.0.0:$health_port" -h "$runtime_dir/health"
            fi
            sleep 1
        done
    }
    start_health_when_ready &
    health_pid=$!
fi

signal_received=0
forward_shutdown() {
    if [ "$signal_received" -ne 0 ]; then
        return
    fi
    signal_received=1

    attempts=0
    while [ ! -s "$child_pid_file" ] && kill -0 "$attached_pid" 2>/dev/null; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 20 ] || break
        sleep 0.05
    done
    child_pid=""
    if [ -r "$child_pid_file" ]; then
        IFS= read -r child_pid <"$child_pid_file" || true
    fi
    case "$child_pid" in
        '' | *[!0-9]*) kill -TERM "$attached_pid" 2>/dev/null || true ;;
        *) kill -INT "$child_pid" 2>/dev/null || true ;;
    esac
}
trap forward_shutdown HUP INT TERM

while :; do
    set +e
    wait "$attached_pid"
    status=$?
    set -e
    if kill -0 "$attached_pid" 2>/dev/null; then
        continue
    fi
    break
done
trap - HUP INT TERM

rm -f "$ready_file" "${ready_file}.tmp" "$child_pid_file" "${child_pid_file}.tmp"
rm -f "$password_input" "$bundle_input"
if [ -n "$health_pid" ]; then
    kill "$health_pid" 2>/dev/null || true
fi
"$herdr_bin" server stop >/dev/null 2>&1 || true
if [ -n "$health_pid" ]; then
    wait "$health_pid" 2>/dev/null || true
fi
rm -rf "$runtime_dir"

exit "$status"
