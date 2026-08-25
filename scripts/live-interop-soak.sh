#!/usr/bin/env bash
# Authoritative E-5 live interop orchestrator. Certification scope is explicit:
# local proves only the pinned topology; public additionally requires retained
# evidence of externally confirmed forwarding.
set -euo pipefail

readonly ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
readonly RUN_TAG="$$"
readonly JAVA_BASE_IMAGE="geti2p/i2p@sha256:c6ddb2b47fe4afee1872325331655ffe3800775f26f8bfeff02ee6a0eb2bbee4"
readonly I2PD_IMAGE="purplei2p/i2pd:release-2.61.0@sha256:422f6715f635d1af0a6ae4937447471477deb6e6719bf5935029be674e4f4cdd"
readonly GO_BASE_IMAGE="golang:1.27-bookworm@sha256:484ef6066fa69acb059fdfeda7ba2b8f7391f2ef6abc6f9b8411e669ebd56466"
readonly JAVA_IMAGE="ivnp-soak-java-${RUN_TAG}"
readonly BINARY_IMAGE="ivnp-soak-binaries-${RUN_TAG}"
readonly JAVA_CONTAINER="ivnp-soak-java-${RUN_TAG}"
readonly I2PD_A_CONTAINER="ivnp-soak-i2pd-a-${RUN_TAG}"
readonly I2PD_B_CONTAINER="ivnp-soak-i2pd-b-${RUN_TAG}"
readonly I2PD_A_VOLUME="ivnp-soak-i2pd-a-data-${RUN_TAG}"
readonly I2PD_B_VOLUME="ivnp-soak-i2pd-b-data-${RUN_TAG}"
readonly INTEROP_NETWORK="ivnp-soak-local-net-${RUN_TAG}"
INTEROP_SUBNET="${IVNP_INTEROP_SUBNET:-}"
BRIDGE_GATEWAY="${IVNP_INTEROP_GATEWAY:-}"
I2PD_A_IP="${IVNP_I2PD_A_IP:-}"
I2PD_B_IP="${IVNP_I2PD_B_IP:-}"
JAVA_IP="${IVNP_JAVA_IP:-}"

MODE="smoke"
SCOPE="local"
SCENARIO=""
SMOKE_DURATION="2m"
WARMUP_TIMEOUT="30m"
ARTIFACT_DIR=""
DURATION_SET=0
WORKDIR=""
ARTIFACT_INITIALIZED=0
BINARY_CONTAINER=""

usage() {
    cat <<'EOF'
Usage:
  scripts/live-interop-soak.sh --mode smoke --scope local --duration 2m --artifacts DIR
  scripts/live-interop-soak.sh --mode smoke --scope local --scenario local-udp-stream --artifacts DIR
  scripts/live-interop-soak.sh --mode certify --scope local --artifacts DIR
  scripts/live-interop-soak.sh --mode certify --scope public --artifacts DIR

certify always measures exactly 3600 seconds; do not use it for a bounded smoke.
Local certification is pinned-topology evidence only and emits
E5_ONE_HOUR_LOCAL_PASS. It is never public or zero-configuration proof. Public
certification additionally requires retained external forwarding evidence and
emits PUBLIC_PASS. Reseed remains enabled in both scopes.
EOF
}

phase() { printf '==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
run_timed() { local seconds="$1"; shift; timeout --foreground --kill-after=10s "${seconds}s" "$@"; }
remove_container() { run_timed 30 docker rm --force "$1" >/dev/null 2>&1 || true; }

capture_logs() {
    [ "$ARTIFACT_INITIALIZED" -eq 1 ] || return 0
    mkdir -p "$ARTIFACT_DIR"
    run_timed 20 docker logs "$JAVA_CONTAINER" >"$ARTIFACT_DIR/java-i2p.log" 2>&1 || true
    run_timed 20 docker logs "$I2PD_A_CONTAINER" >"$ARTIFACT_DIR/i2pd-a.log" 2>&1 || true
    run_timed 20 docker logs "$I2PD_B_CONTAINER" >"$ARTIFACT_DIR/i2pd-b.log" 2>&1 || true
    mkdir -p "$ARTIFACT_DIR/java-router-logs"
    run_timed 20 docker cp "$JAVA_CONTAINER:/i2p/.i2p/logs/." "$ARTIFACT_DIR/java-router-logs/" >/dev/null 2>&1 || true
    run_timed 20 docker exec "$JAVA_CONTAINER" sed -n '/^explicitPeers=/p;/^i2np\.allowLocal=/p;/^i2np\.ntcp\.hostname=/p;/^i2np\.ntcp\.ipv6=/p;/^i2np\.udp\.host=/p;/^i2np\.udp\.ipv6=/p;/^router\.blocklist\.enable=/p' /i2p/.i2p/router.config >"$ARTIFACT_DIR/java-local-policy.conf" 2>/dev/null || true
}

finalize_preflight_artifacts() {
    [ "$ARTIFACT_INITIALIZED" -eq 1 ] || return 0
    [ -f "$ARTIFACT_DIR/summary.json" ] && return 0
    : >"$ARTIFACT_DIR/events.jsonl"
    : >"$ARTIFACT_DIR/samples.jsonl"
    cat >"$ARTIFACT_DIR/manifest.json" <<EOF
{"schema":"ivnp.soak/v1","mode":"$MODE","scope":"$SCOPE","measured_monotonic_seconds":0,"orchestration_completed":false}
EOF
    cat >"$ARTIFACT_DIR/summary.json" <<EOF
{"schema":"ivnp.soak/v1","mode":"$MODE","scope":"$SCOPE","verdict":"not_run","E5_ONE_HOUR":"not_run","reason":"orchestration or prerequisite failed; inspect retained logs and preflight evidence"}
EOF
    : >"$ARTIFACT_DIR/checksums.sha256"
    local file digest
    for file in "$ARTIFACT_DIR"/*; do
        [ -f "$file" ] || continue
        [ "${file##*/}" = checksums.sha256 ] && continue
        digest="$(sha256sum "$file")"
        printf '%s  %s\n' "${digest%% *}" "${file##*/}" >>"$ARTIFACT_DIR/checksums.sha256"
    done
}

cleanup() {
    local status="$?"
    trap - EXIT INT TERM
    capture_logs
    [ -z "$BINARY_CONTAINER" ] || remove_container "$BINARY_CONTAINER"
    finalize_preflight_artifacts
    remove_container "$JAVA_CONTAINER"
    remove_container "$I2PD_A_CONTAINER"
    remove_container "$I2PD_B_CONTAINER"
    run_timed 30 docker network rm "$INTEROP_NETWORK" >/dev/null 2>&1 || true
    run_timed 30 docker volume rm "$I2PD_A_VOLUME" >/dev/null 2>&1 || true
    run_timed 30 docker volume rm "$I2PD_B_VOLUME" >/dev/null 2>&1 || true
    run_timed 30 docker image rm "$JAVA_IMAGE" >/dev/null 2>&1 || true
    run_timed 30 docker image rm "$BINARY_IMAGE" >/dev/null 2>&1 || true
    [ -z "$WORKDIR" ] || rm -rf -- "$WORKDIR"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode) [ "$#" -ge 2 ] || fail "--mode requires smoke or certify"; MODE="$2"; shift 2 ;;
        --scope) [ "$#" -ge 2 ] || fail "--scope requires local or public"; SCOPE="$2"; shift 2 ;;
        --scenario) [ "$#" -ge 2 ] || fail "--scenario requires local-udp-stream"; SCENARIO="$2"; shift 2 ;;
        --duration) [ "$#" -ge 2 ] || fail "--duration requires a Go duration"; DURATION_SET=1; SMOKE_DURATION="$2"; shift 2 ;;
        --warmup-timeout) [ "$#" -ge 2 ] || fail "--warmup-timeout requires a Go duration"; WARMUP_TIMEOUT="$2"; shift 2 ;;
        --artifacts) [ "$#" -ge 2 ] || fail "--artifacts requires a directory"; ARTIFACT_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
case "$MODE" in smoke|certify) ;; *) fail "--mode must be smoke or certify" ;; esac
case "$SCOPE" in local|public) ;; *) fail "--scope must be local or public" ;; esac
case "$SCENARIO" in ""|local-udp-stream) ;; *) fail "--scenario must be local-udp-stream" ;; esac
[ -n "$ARTIFACT_DIR" ] || fail "--artifacts is required"
[ "$MODE" != certify ] || [ "$DURATION_SET" -eq 0 ] || fail "--duration is forbidden with --mode certify"
[ "$MODE" != smoke ] || [ "$SCOPE" = local ] || fail "smoke supports only --scope local"
[ -z "$SCENARIO" ] || { [ "$MODE" = smoke ] && [ "$SCOPE" = local ]; } || fail "--scenario requires --mode smoke --scope local"

cd "$ROOT_DIR"
for prerequisite in docker curl go timeout sha256sum sed python3; do
    command -v "$prerequisite" >/dev/null 2>&1 || fail "missing required command: ${prerequisite}"
done
run_timed 20 docker info >/dev/null || fail "Docker daemon is not available"

create_interop_network() {
    local attempt base
    local scope_args=()
    if [ "$SCOPE" = local ]; then
        scope_args+=(--internal)
    fi
    if [ -n "$INTEROP_SUBNET" ] || [ -n "$BRIDGE_GATEWAY" ] || [ -n "$I2PD_A_IP" ] || [ -n "$I2PD_B_IP" ] || [ -n "$JAVA_IP" ]; then
        [ -n "$INTEROP_SUBNET" ] && [ -n "$BRIDGE_GATEWAY" ] && [ -n "$I2PD_A_IP" ] && [ -n "$I2PD_B_IP" ] && [ -n "$JAVA_IP" ] ||
            fail "IVNP_INTEROP_SUBNET, IVNP_INTEROP_GATEWAY, IVNP_I2PD_A_IP, IVNP_I2PD_B_IP, and IVNP_JAVA_IP must be set together"
        run_timed 30 docker network create --driver bridge "${scope_args[@]}" --subnet "$INTEROP_SUBNET" --gateway "$BRIDGE_GATEWAY" "$INTEROP_NETWORK" >/dev/null ||
            fail "cannot create requested interop subnet $INTEROP_SUBNET"
        return
    fi
    # i2pd rejects RFC1918 peers before transport authentication, while IVNP's
    # tunnel diversity policy rejects peers in the same /16. Allocate a narrow
    # isolated non-special /14 so the three native routers occupy distinct
    # /16s without routing an entire public /8 through Docker.
    for attempt in $(seq 0 63); do
        base=$((4 * (2 + (RUN_TAG + attempt) % 60)))
        if run_timed 30 docker network create --driver bridge "${scope_args[@]}" --subnet "11.${base}.0.0/14" --gateway "11.${base}.0.1" "$INTEROP_NETWORK" >/dev/null 2>&1; then
            INTEROP_SUBNET="11.${base}.0.0/14"
            BRIDGE_GATEWAY="11.${base}.0.1"
            I2PD_A_IP="11.${base}.0.2"
            I2PD_B_IP="11.$((base + 1)).0.2"
            JAVA_IP="11.$((base + 2)).0.2"
            return
        fi
    done
    fail "cannot allocate an isolated interop subnet; set all IVNP_INTEROP_* topology variables explicitly"
}
create_interop_network

umask 077
mkdir -p "$ARTIFACT_DIR"
shopt -s nullglob dotglob
ARTIFACT_ENTRIES=("$ARTIFACT_DIR"/*)
shopt -u nullglob dotglob
[ "${#ARTIFACT_ENTRIES[@]}" -eq 0 ] || fail "artifact directory must be empty: $ARTIFACT_DIR"
unset ARTIFACT_ENTRIES
ARTIFACT_DIR="$(CDPATH= cd -- "$ARTIFACT_DIR" && pwd)"
chmod 700 "$ARTIFACT_DIR"
ARTIFACT_INITIALIZED=1
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ivnp-e5.XXXXXX")"
chmod 700 "$WORKDIR"
mkdir -p "$WORKDIR/java" "$WORKDIR/i2pd-a" "$WORKDIR/i2pd-b" "$WORKDIR/native" "$WORKDIR/state" "$WORKDIR/data"

RUN_ID="$(tr -d '-' </proc/sys/kernel/random/uuid)"
PUBLIC_IP="${IVNP_PUBLIC_IP:-}"
PUBLIC_REACHABILITY="not_requested"
PUBLIC_EVIDENCE=""
PUBLIC_PROBE_KEY=""
if [ "$SCOPE" = local ]; then
    touch "$WORKDIR/java/.i2pnoreseed"
fi
ADVERTISE_HOST="$BRIDGE_GATEWAY"
if [ "$SCOPE" = public ]; then
    if [ -z "$PUBLIC_IP" ]; then
        PUBLIC_IP="$(run_timed 15 curl -fsS --connect-timeout 5 --max-time 10 https://api.ipify.org)" || fail "cannot discover public IPv4; set IVNP_PUBLIC_IP"
    fi
    [[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "IVNP_PUBLIC_IP must be an IPv4 literal"
    PUBLIC_EVIDENCE="${IVNP_PUBLIC_REACHABILITY_EVIDENCE:-}"
    PUBLIC_PROBE_KEY="${IVNP_PUBLIC_PROBE_PUBLIC_KEY:-}"
    [ -n "$PUBLIC_EVIDENCE" ] || fail "public scope requires IVNP_PUBLIC_REACHABILITY_EVIDENCE for an asynchronously produced signed probe result"
    [ -n "$PUBLIC_PROBE_KEY" ] || fail "public scope requires IVNP_PUBLIC_PROBE_PUBLIC_KEY"
    PUBLIC_REACHABILITY="signed_external_probe_required"
    ADVERTISE_HOST="$PUBLIC_IP"
elif [ -n "$PUBLIC_IP" ] && ! [[ "$PUBLIC_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    fail "IVNP_PUBLIC_IP must be an IPv4 literal"
fi

APP_PORT_BASE=$((30000 + (RUN_TAG % 2000) * 10))
IVNP_NTCP_PORT=$APP_PORT_BASE
IVNP_SSU2_PORT=$((APP_PORT_BASE + 1))
if [ "$SCOPE" = public ]; then
    IVNP_NTCP_PORT=29442
    IVNP_SSU2_PORT=29443
fi
IVNP_SAM_PORT=$((APP_PORT_BASE + 2))
IVNP_SAM_UDP_PORT=$((APP_PORT_BASE + 3))
IVNP_METRICS_PORT=$((APP_PORT_BASE + 4))
IVNP_CONTROL_PORT=$((APP_PORT_BASE + 5))
JAVA_SAM_ADDRESS="${JAVA_IP}:7656"
I2PD_A_SAM_ADDRESS="${I2PD_A_IP}:27656"
I2PD_B_SAM_ADDRESS="${I2PD_B_IP}:28656"
IVNP_SAM_ADDRESS="127.0.0.1:${IVNP_SAM_PORT}"
IVNP_METRICS_URL="http://127.0.0.1:${IVNP_METRICS_PORT}"
IVNP_CONTROL_URL="http://127.0.0.1:${IVNP_CONTROL_PORT}"
IVNP_RESEED_ENABLED=true
IVNP_RESEED_ENDPOINTS=""
if [ "$SCOPE" = local ]; then
    IVNP_RESEED_ENABLED=false
    IVNP_RESEED_ENDPOINTS="endpoints ="
fi
cat >"$ARTIFACT_DIR/network-preflight.conf" <<EOF
scope=$SCOPE
local_subnet=$INTEROP_SUBNET
bridge_gateway=$BRIDGE_GATEWAY
i2pd_a_ip=$I2PD_A_IP
i2pd_b_ip=$I2PD_B_IP
java_ip=$JAVA_IP
java_sam=$JAVA_SAM_ADDRESS
i2pd_a_sam=$I2PD_A_SAM_ADDRESS
i2pd_b_sam=$I2PD_B_SAM_ADDRESS
ivnp_ntcp_port=$IVNP_NTCP_PORT
ivnp_ssu2_port=$IVNP_SSU2_PORT
ivnp_sam=$IVNP_SAM_ADDRESS
run_id=$RUN_ID
public_ip=${PUBLIC_IP:-not_requested}
public_reachability=$PUBLIC_REACHABILITY
reseed=$IVNP_RESEED_ENABLED
EOF

phase "building pinned Java target and IVNP binaries"
run_timed 900 docker build --file Containerfile --target java-i2p --tag "$JAVA_IMAGE" .
run_timed 900 docker build --file Containerfile --target soak-binaries --tag "$BINARY_IMAGE" .
BINARY_CONTAINER="$(run_timed 30 docker create "$BINARY_IMAGE" /ivnp)"
run_timed 30 docker cp "$BINARY_CONTAINER:/ivnp" "$WORKDIR/ivnp"
run_timed 30 docker cp "$BINARY_CONTAINER:/ivnp-soak" "$WORKDIR/ivnp-soak"
remove_container "$BINARY_CONTAINER"; BINARY_CONTAINER=""
chmod 700 "$WORKDIR/ivnp" "$WORKDIR/ivnp-soak"
sha256sum "$WORKDIR/ivnp" >"$ARTIFACT_DIR/ivnp-binary.sha256"
phase "exercising secure actual-binary first start and restart defaults"
FIRST_RUN_DIR="$WORKDIR/first-run-defaults"
mkdir -p "$FIRST_RUN_DIR"
first_status=0
run_timed 1 "$WORKDIR/ivnp" -config "$FIRST_RUN_DIR/ivnp.conf" >"$ARTIFACT_DIR/binary-first-start.log" 2>&1 || first_status=$?
[ "$first_status" -eq 0 ] || [ "$first_status" -eq 124 ] || fail "actual binary first start failed with status $first_status"
[ -f "$FIRST_RUN_DIR/ivnp.conf" ] || fail "actual binary did not atomically create its first-run configuration"
[ "$(stat -c '%a' "$FIRST_RUN_DIR/ivnp.conf")" = 600 ] || fail "actual binary first-run configuration is not private"
[ -f "$FIRST_RUN_DIR/state/router.keys" ] || fail "actual binary first start did not persist router key material"
first_key_digest="$(sha256sum "$FIRST_RUN_DIR/state/router.keys")"
restart_status=0
run_timed 1 "$WORKDIR/ivnp" -config "$FIRST_RUN_DIR/ivnp.conf" >"$ARTIFACT_DIR/binary-first-restart.log" 2>&1 || restart_status=$?
[ "$restart_status" -eq 0 ] || [ "$restart_status" -eq 124 ] || fail "actual binary first restart failed with status $restart_status"
restart_key_digest="$(sha256sum "$FIRST_RUN_DIR/state/router.keys")"
[ "${first_key_digest%% *}" = "${restart_key_digest%% *}" ] || fail "actual binary router identity changed across first restart"
printf 'first_start_status=%s\nrestart_status=%s\nconfig_mode=600\nrouter_key_sha256=%s\ncontrol_default=disabled\n' \
    "$first_status" "$restart_status" "${first_key_digest%% *}" >"$ARTIFACT_DIR/binary-first-run.status"
run_timed 10 docker image inspect "$I2PD_IMAGE" >/dev/null 2>&1 || run_timed 600 docker pull "$I2PD_IMAGE" >/dev/null
JAVA_IMAGE_ID="$(run_timed 10 docker image inspect --format '{{.Id}}' "$JAVA_IMAGE")"
I2PD_IMAGE_ID="$(run_timed 10 docker image inspect --format '{{.Id}}' "$I2PD_IMAGE")"
BINARY_IMAGE_ID="$(run_timed 10 docker image inspect --format '{{.Id}}' "$BINARY_IMAGE")"

configure_java_local_router() {
    [ "$SCOPE" = local ] || return 0
    # Java I2P rejects bridge-local transport addresses in both its public
    # routability check and the bundled bogon blocklist. Apply these settings
    # only after the disposable router has completed its supported first-run
    # initialization, so clients.config and the SAM bridge are also installed.
    cat >>"$WORKDIR/java/router.config" <<EOF
i2np.allowLocal=true
router.blocklist.enable=false
router.reseedDisable=true
router.floodfillParticipant=true
i2np.ntcp.hostname=$JAVA_IP
i2np.udp.host=$JAVA_IP
i2np.ntcp.ipv6=false
i2np.udp.ipv6=false
EOF
    cat >"$ARTIFACT_DIR/java-local-policy.conf" <<EOF
i2np.allowLocal=true
router.blocklist.enable=false
router.reseedDisable=true
router.floodfillParticipant=true
i2np.ntcp.hostname=$JAVA_IP
i2np.udp.host=$JAVA_IP
i2np.ntcp.ipv6=false
i2np.udp.ipv6=false
EOF
    if [ "${IVNP_JAVA_INTEROP_DEBUG:-0}" = 1 ]; then
        cat >>"$WORKDIR/java/logger.config" <<'EOF'
logger.record.net.i2p.router.crypto.ratchet.ECIESAEADEngine=DEBUG
logger.record.net.i2p.client.streaming.impl=DEBUG
logger.minimumOnScreenLevel=DEBUG
EOF
    fi
}

write_i2pd_config() {
    local path="$1" ip="$2" ntcp_port="$3" sam_port="$4" floodfill="$5" reseed_urls=""
    if [ "$SCOPE" = local ]; then
        reseed_urls="urls ="
    fi
    cat >"$path" <<EOF
log = stdout
loglevel = info
ipv4 = true
ipv6 = false
floodfill = $floodfill
nat = false
reservedrange = false
host = $ip
[ntcp2]
enabled = true
published = true
port = $ntcp_port
[ssu2]
enabled = false
published = false
[http]
enabled = false
[httpproxy]
enabled = false
[socksproxy]
enabled = false
[sam]
enabled = true
address = 0.0.0.0
port = $sam_port
[i2cp]
enabled = false
[upnp]
enabled = false
[reseed]
verify = true
threshold = 0
$reseed_urls
[exploratory]
inbound.length = 0
outbound.length = 0
inbound.quantity = 1
outbound.quantity = 1
EOF
    chmod 600 "$path"
}
write_i2pd_config "$WORKDIR/i2pd-a/i2pd.conf" "$I2PD_A_IP" 28442 27656 true
write_i2pd_config "$WORKDIR/i2pd-b/i2pd.conf" "$I2PD_B_IP" 28542 28656 true
cp "$WORKDIR/i2pd-a/i2pd.conf" "$ARTIFACT_DIR/i2pd-a.conf"
cp "$WORKDIR/i2pd-b/i2pd.conf" "$ARTIFACT_DIR/i2pd-b.conf"

run_timed 30 docker volume create "$I2PD_A_VOLUME" >/dev/null
run_timed 30 docker volume create "$I2PD_B_VOLUME" >/dev/null
initialize_i2pd_volume() {
    local volume="$1" config_path="$2"
    run_timed 60 docker run --rm --user 0 --entrypoint sh -v "${volume}:/home/i2pd/data" -v "${config_path}:/tmp/i2pd.conf:ro" "$I2PD_IMAGE" -c 'cp /tmp/i2pd.conf /home/i2pd/data/i2pd.conf && chown -R 100:65533 /home/i2pd/data && chmod 700 /home/i2pd/data && chmod 600 /home/i2pd/data/i2pd.conf'
}
initialize_i2pd_volume "$I2PD_A_VOLUME" "$WORKDIR/i2pd-a/i2pd.conf"
initialize_i2pd_volume "$I2PD_B_VOLUME" "$WORKDIR/i2pd-b/i2pd.conf"

phase "starting pinned Java I2P, i2pd tunnel peer, and i2pd floodfill concurrently"
run_timed 60 docker run -d --name "$JAVA_CONTAINER" --network "$INTEROP_NETWORK" --ip "$JAVA_IP" -e "IP_ADDR=$JAVA_IP" -e EXT_PORT=27442 -e JVM_XMX=512m -e "I2P_UID=$(id -u)" -e "I2P_GID=$(id -g)" -v "$WORKDIR/java:/i2p/.i2p" "$JAVA_IMAGE" >/dev/null
run_timed 60 docker run -d --name "$I2PD_A_CONTAINER" --network "$INTEROP_NETWORK" --ip "$I2PD_A_IP" -v "${I2PD_A_VOLUME}:/home/i2pd/data" "$I2PD_IMAGE" >/dev/null
run_timed 60 docker run -d --name "$I2PD_B_CONTAINER" --network "$INTEROP_NETWORK" --ip "$I2PD_B_IP" -v "${I2PD_B_VOLUME}:/home/i2pd/data" "$I2PD_IMAGE" >/dev/null

all_running() {
    [ "$(docker inspect --format '{{.State.Running}}' "$JAVA_CONTAINER" 2>/dev/null || true)" = true ] &&
    [ "$(docker inspect --format '{{.State.Running}}' "$I2PD_A_CONTAINER" 2>/dev/null || true)" = true ] &&
    [ "$(docker inspect --format '{{.State.Running}}' "$I2PD_B_CONTAINER" 2>/dev/null || true)" = true ]
}
wait_tcp() {
    local address="$1" description="$2" deadline=$((SECONDS + 600)) host="${1%:*}" port="${1##*:}"
    while [ "$SECONDS" -lt "$deadline" ]; do
        all_running || fail "a pinned router exited before ${description}"
        if run_timed 3 bash -c 'exec 3<>/dev/tcp/$1/$2' _ "$host" "$port" 2>/dev/null; then phase "ready: ${description} at ${address}"; return 0; fi
        sleep 2
    done
    fail "timed out waiting for ${description} at ${address}"
}
wait_tcp "$JAVA_SAM_ADDRESS" "Java SAM"
wait_tcp "$I2PD_A_SAM_ADDRESS" "i2pd-a SAM"
wait_tcp "$I2PD_B_SAM_ADDRESS" "i2pd-b SAM"
configure_java_local_router

copy_current_router_infos() {
    run_timed 30 docker cp "$JAVA_CONTAINER:/i2p/.i2p/router.info" "$WORKDIR/native/java.router.info"
    run_timed 30 docker cp "$I2PD_A_CONTAINER:/home/i2pd/data/router.info" "$WORKDIR/native/i2pd-a.router.info"
    run_timed 30 docker cp "$I2PD_B_CONTAINER:/home/i2pd/data/router.info" "$WORKDIR/native/i2pd-b.router.info"
}
router_hash() {
    python3 - "$1" <<'PY'
import base64, hashlib, sys
wire = open(sys.argv[1], 'rb').read()
if len(wire) < 387:
    raise SystemExit('RouterInfo too short')
cert_len = int.from_bytes(wire[385:387], 'big')
identity = wire[:387 + cert_len]
print(base64.b64encode(hashlib.sha256(identity).digest()).decode().translate(str.maketrans('+/', '-~')))
PY
}

router_caps() {
    python3 - "$1" <<'PY'
import sys

wire = open(sys.argv[1], 'rb').read()
cert_len = int.from_bytes(wire[385:387], 'big')
offset = 387 + cert_len + 8
address_count = wire[offset]
offset += 1

def skip_mapping(data, pos):
    size = int.from_bytes(data[pos:pos + 2], 'big')
    return pos + 2 + size

for _ in range(address_count):
    style_len = wire[offset + 9]
    offset += 10 + style_len
    offset = skip_mapping(wire, offset)
peer_count = wire[offset]
offset += 1 + 32 * peer_count
mapping_end = skip_mapping(wire, offset)
offset += 2
while offset < mapping_end:
    key_len = wire[offset]
    offset += 1
    key = wire[offset:offset + key_len]
    offset += key_len
    if wire[offset] != ord('='):
        raise SystemExit('malformed RouterInfo mapping')
    offset += 1
    value_len = wire[offset]
    offset += 1
    value = wire[offset:offset + value_len]
    offset += value_len
    if wire[offset] != ord(';'):
        raise SystemExit('malformed RouterInfo mapping')
    offset += 1
    if key == b'caps':
        print(value.decode('ascii'))
        break
PY
}
seed_java() {
    local source="$1" hash="$2" directory
    directory="$WORKDIR/java/netDb/r${hash:0:1}"
    mkdir -p "$directory"
    cp "$source" "$directory/routerInfo-${hash}.dat"
}
seed_i2pd() {
    local volume="$1" source="$2" hash="$3" source_dir source_name
    source_dir="$(dirname "$source")"; source_name="$(basename "$source")"
    run_timed 60 docker run --rm --user 0 --entrypoint sh -v "${volume}:/home/i2pd/data" -v "${source_dir}:/seed:ro" "$I2PD_IMAGE" -c "mkdir -p '/home/i2pd/data/netDb/r${hash:0:1}' && cp '/seed/${source_name}' '/home/i2pd/data/netDb/r${hash:0:1}/routerInfo-${hash}.dat' && chown -R 100:65533 /home/i2pd/data/netDb"
}

# First snapshot supplies supported filesystem seeds. Restart the native routers
# once, then take the exact current signed snapshots consumed by IVNP.
copy_current_router_infos
JAVA_HASH="$(router_hash "$WORKDIR/native/java.router.info")"
I2PD_A_HASH="$(router_hash "$WORKDIR/native/i2pd-a.router.info")"
I2PD_B_HASH="$(router_hash "$WORKDIR/native/i2pd-b.router.info")"
run_timed 90 docker stop --time 60 "$JAVA_CONTAINER" "$I2PD_A_CONTAINER" "$I2PD_B_CONTAINER" >/dev/null
seed_java "$WORKDIR/native/i2pd-a.router.info" "$I2PD_A_HASH"
seed_java "$WORKDIR/native/i2pd-b.router.info" "$I2PD_B_HASH"
seed_i2pd "$I2PD_A_VOLUME" "$WORKDIR/native/java.router.info" "$JAVA_HASH"
seed_i2pd "$I2PD_A_VOLUME" "$WORKDIR/native/i2pd-b.router.info" "$I2PD_B_HASH"
seed_i2pd "$I2PD_B_VOLUME" "$WORKDIR/native/java.router.info" "$JAVA_HASH"
seed_i2pd "$I2PD_B_VOLUME" "$WORKDIR/native/i2pd-a.router.info" "$I2PD_A_HASH"
run_timed 60 docker start "$JAVA_CONTAINER" "$I2PD_A_CONTAINER" "$I2PD_B_CONTAINER" >/dev/null
wait_tcp "$JAVA_SAM_ADDRESS" "restarted Java SAM"
wait_tcp "$I2PD_A_SAM_ADDRESS" "restarted i2pd-a SAM"
wait_tcp "$I2PD_B_SAM_ADDRESS" "restarted i2pd-b SAM"
copy_current_router_infos
JAVA_HASH="$(router_hash "$WORKDIR/native/java.router.info")"
I2PD_A_HASH="$(router_hash "$WORKDIR/native/i2pd-a.router.info")"
I2PD_B_HASH="$(router_hash "$WORKDIR/native/i2pd-b.router.info")"

# Install the exact post-restart signed records through each implementation's
# supported NetDB filesystem, then restart once more so every native scanner
# admits the same identities before IVNP starts.
run_timed 90 docker stop --time 60 "$JAVA_CONTAINER" "$I2PD_A_CONTAINER" "$I2PD_B_CONTAINER" >/dev/null
rm -rf -- "$WORKDIR/java/netDb"
mkdir -p "$WORKDIR/java/netDb"
reset_i2pd_netdb() {
    local volume="$1"
    run_timed 60 docker run --rm --user 0 --entrypoint sh -v "${volume}:/home/i2pd/data" "$I2PD_IMAGE" -c 'rm -rf /home/i2pd/data/netDb && mkdir -p /home/i2pd/data/netDb && chown -R 100:65533 /home/i2pd/data/netDb'
}
reset_i2pd_netdb "$I2PD_A_VOLUME"
reset_i2pd_netdb "$I2PD_B_VOLUME"
seed_java "$WORKDIR/native/i2pd-a.router.info" "$I2PD_A_HASH"
seed_java "$WORKDIR/native/i2pd-b.router.info" "$I2PD_B_HASH"
seed_i2pd "$I2PD_A_VOLUME" "$WORKDIR/native/java.router.info" "$JAVA_HASH"
seed_i2pd "$I2PD_A_VOLUME" "$WORKDIR/native/i2pd-b.router.info" "$I2PD_B_HASH"
seed_i2pd "$I2PD_B_VOLUME" "$WORKDIR/native/java.router.info" "$JAVA_HASH"
seed_i2pd "$I2PD_B_VOLUME" "$WORKDIR/native/i2pd-a.router.info" "$I2PD_A_HASH"
run_timed 60 docker start "$JAVA_CONTAINER" "$I2PD_A_CONTAINER" "$I2PD_B_CONTAINER" >/dev/null
wait_tcp "$JAVA_SAM_ADDRESS" "seeded Java SAM"
wait_tcp "$I2PD_A_SAM_ADDRESS" "seeded i2pd-a SAM"
wait_tcp "$I2PD_B_SAM_ADDRESS" "seeded i2pd-b SAM"
copy_current_router_infos
[ "$(router_hash "$WORKDIR/native/java.router.info")" = "$JAVA_HASH" ] || fail "Java router identity changed across seeded restart"
[ "$(router_hash "$WORKDIR/native/i2pd-a.router.info")" = "$I2PD_A_HASH" ] || fail "i2pd-a router identity changed across seeded restart"
[ "$(router_hash "$WORKDIR/native/i2pd-b.router.info")" = "$I2PD_B_HASH" ] || fail "i2pd-b router identity changed across seeded restart"
# Java's fresh peer profiles are primed by starting the two native SAM
# endpoints before its own session. Both pinned i2pd routers remain floodfills
# for the publication and lookup gates.
if [ -z "$SCENARIO" ]; then
    phase "running native NTCP2 and ShortTunnelBuild prerequisites against both pinned i2pd RouterInfos"
    run_timed 180 env IVNP_I2PD_INTEGRATION=1 IVNP_I2PD_ROUTER_INFO="$WORKDIR/native/i2pd-a.router.info" \
        go test -tags=integration -count=1 -run '^TestI2PDNTCP2Interop$' -timeout=3m ./network/router \
        >"$ARTIFACT_DIR/i2pd-a-ntcp2-prerequisite.log" 2>&1 ||
        { cat "$ARTIFACT_DIR/i2pd-a-ntcp2-prerequisite.log" >&2; fail "i2pd-a NTCP2 prerequisite failed"; }
    run_timed 240 env IVNP_I2PD_INTEGRATION=1 IVNP_I2PD_ROUTER_INFO="$WORKDIR/native/i2pd-a.router.info" IVNP_I2PD_REPLY_ROUTER_INFO="$WORKDIR/native/i2pd-b.router.info" \
        go test -tags=integration -count=1 -run '^TestI2PDShortTunnelBuildDiagnostic$' -timeout=4m ./network/router \
        >"$ARTIFACT_DIR/i2pd-a-short-build-prerequisite.log" 2>&1 ||
        { cat "$ARTIFACT_DIR/i2pd-a-short-build-prerequisite.log" >&2; fail "i2pd-a ShortTunnelBuild prerequisite failed"; }
    run_timed 180 env IVNP_I2PD_INTEGRATION=1 IVNP_I2PD_ROUTER_INFO="$WORKDIR/native/i2pd-b.router.info" \
        go test -tags=integration -count=1 -run '^TestI2PDNTCP2Interop$' -timeout=3m ./network/router \
        >"$ARTIFACT_DIR/i2pd-b-ntcp2-prerequisite.log" 2>&1 ||
        { cat "$ARTIFACT_DIR/i2pd-b-ntcp2-prerequisite.log" >&2; fail "i2pd-b NTCP2 prerequisite failed"; }
    run_timed 240 env IVNP_I2PD_INTEGRATION=1 IVNP_I2PD_ROUTER_INFO="$WORKDIR/native/i2pd-b.router.info" IVNP_I2PD_REPLY_ROUTER_INFO="$WORKDIR/native/i2pd-a.router.info" \
        go test -tags=integration -count=1 -run '^TestI2PDShortTunnelBuildDiagnostic$' -timeout=4m ./network/router \
        >"$ARTIFACT_DIR/i2pd-b-short-build-prerequisite.log" 2>&1 ||
        { cat "$ARTIFACT_DIR/i2pd-b-short-build-prerequisite.log" >&2; fail "i2pd-b ShortTunnelBuild prerequisite failed"; }
    printf '%s\n' ntcp2_and_short_build_both_i2pd_pass >"$ARTIFACT_DIR/native-prerequisites.status"
else
    printf '%s\n' skipped_for_focused_scenario >"$ARTIFACT_DIR/native-prerequisites.status"
fi

copy_current_router_infos
I2PD_A_CAPS="$(router_caps "$WORKDIR/native/i2pd-a.router.info")"
I2PD_B_CAPS="$(router_caps "$WORKDIR/native/i2pd-b.router.info")"
[[ "$I2PD_A_CAPS" == *f* ]] || fail "i2pd-a publication peer lacks floodfill capability (caps=$I2PD_A_CAPS)"
[[ "$I2PD_B_CAPS" == *f* ]] || fail "i2pd-b publication peer lacks floodfill capability (caps=$I2PD_B_CAPS)"

if [ "$SCOPE" = local ]; then
    # Keep Java's restricted-topology client tunnels on the peer whose native
    # transport/build prerequisite was exercised first. A second explicit peer
    # may be profile-quarantined while it is used as the reply floodfill; Java
    # then falls back to zero-hop and stops publishing the application LS2.
    printf 'explicitPeers=%s\n' "$I2PD_A_HASH" >>"$WORKDIR/java/router.config"
fi
# Refresh the final signed records in Java's NetDB after the native transport
# prerequisites, before its peer profiles are primed by native SAM traffic.
run_timed 90 docker stop --time 60 "$JAVA_CONTAINER" >/dev/null
seed_java "$WORKDIR/native/i2pd-a.router.info" "$I2PD_A_HASH"
seed_java "$WORKDIR/native/i2pd-b.router.info" "$I2PD_B_HASH"
run_timed 60 docker start "$JAVA_CONTAINER" >/dev/null
wait_tcp "$JAVA_SAM_ADDRESS" "reachable-seeded Java SAM"
copy_current_router_infos
[ "$(router_hash "$WORKDIR/native/java.router.info")" = "$JAVA_HASH" ] || fail "Java router identity changed across reachable-seeded restart"
cp "$WORKDIR/native/java.router.info" "$ARTIFACT_DIR/java.router.info"
cp "$WORKDIR/native/i2pd-a.router.info" "$ARTIFACT_DIR/i2pd-a.router.info"
cp "$WORKDIR/native/i2pd-b.router.info" "$ARTIFACT_DIR/i2pd-b.router.info"
printf 'java=%s\ni2pd-a=%s\ni2pd-b=%s\n' "$JAVA_HASH" "$I2PD_A_HASH" "$I2PD_B_HASH" >"$ARTIFACT_DIR/pinned-router-hashes.txt"


CONTROL_TOKEN="ivnp-control-$(cat /proc/sys/kernel/random/uuid)"
printf '%s\n' "$CONTROL_TOKEN" >"$WORKDIR/control-token"
chmod 600 "$WORKDIR/control-token"
cat >"$WORKDIR/ivnp.conf" <<EOF
[paths]
data_dir = $WORKDIR/data
state_dir = $WORKDIR/state
state_path = $WORKDIR/state/router.state
key_path = $WORKDIR/state/router.keys
[netdb]
bootstrap_router_info_files = $WORKDIR/native/i2pd-a.router.info,$WORKDIR/native/i2pd-b.router.info,$WORKDIR/native/java.router.info
[reseed]
enabled = $IVNP_RESEED_ENABLED
$IVNP_RESEED_ENDPOINTS
[tunnel]
hops = 1
inbound_target = 1
outbound_target = 1
pool_capacity = 2
maintenance_interval = 5s
[ntcp2]
enabled = true
bind_host = 0.0.0.0
bind_port = $IVNP_NTCP_PORT
advertise_host = $ADVERTISE_HOST
advertise_port = $IVNP_NTCP_PORT
[ssu2]
enabled = true
bind_host = 0.0.0.0
bind_port = $IVNP_SSU2_PORT
advertise_host = $ADVERTISE_HOST
advertise_port = $IVNP_SSU2_PORT
[sam]
enabled = true
listen_host = 127.0.0.1
listen_port = $IVNP_SAM_PORT
udp_host = 127.0.0.1
udp_port = $IVNP_SAM_UDP_PORT
[metrics]
enabled = true
listen_host = 127.0.0.1
listen_port = $IVNP_METRICS_PORT
[control]
enabled = true
listen_host = 127.0.0.1
listen_port = $IVNP_CONTROL_PORT
bearer_token = $CONTROL_TOKEN
[log]
level = debug
format = json
EOF
chmod 600 "$WORKDIR/ivnp.conf"
sed 's/^bearer_token = .*/bearer_token = [REDACTED]/' "$WORKDIR/ivnp.conf" >"$ARTIFACT_DIR/ivnp.conf.redacted"
chmod 600 "$ARTIFACT_DIR/ivnp.conf.redacted"

cat >"$ARTIFACT_DIR/java-orchestration.conf" <<EOF
image=$JAVA_BASE_IMAGE
resolved_image_id=$JAVA_IMAGE_ID
network=$INTEROP_NETWORK
sam=$JAVA_SAM_ADDRESS
ntcp2_ssu2_port=27442
scope=$SCOPE
EOF
RUNNER_ARGS=(
    --mode "$MODE" --scope "$SCOPE" --run-id "$RUN_ID" --artifacts "$ARTIFACT_DIR" --warmup-timeout "$WARMUP_TIMEOUT"
    --ivnp-binary "$WORKDIR/ivnp" --ivnp-config "$WORKDIR/ivnp.conf" --control-token-file "$WORKDIR/control-token"
    --java-container "$JAVA_CONTAINER" --i2pd-a-container "$I2PD_A_CONTAINER" --i2pd-b-container "$I2PD_B_CONTAINER"
    --java-image-id "$JAVA_IMAGE_ID" --i2pd-image-id "$I2PD_IMAGE_ID" --builder-image-id "$BINARY_IMAGE_ID"
    --pinned-router-hashes "java=$JAVA_HASH,i2pd-a=$I2PD_A_HASH,i2pd-b=$I2PD_B_HASH"
    --java-sam "$JAVA_SAM_ADDRESS" --i2pd-a-sam "$I2PD_A_SAM_ADDRESS" --i2pd-b-sam "$I2PD_B_SAM_ADDRESS"
    --ivnp-sam "$IVNP_SAM_ADDRESS" --ivnp-sam-udp "127.0.0.1:${IVNP_SAM_UDP_PORT}" --metrics-url "$IVNP_METRICS_URL" --control-url "$IVNP_CONTROL_URL"
    --stream-load-concurrency "${IVNP_STREAM_LOAD_CONCURRENCY:-6}" --stream-load-rate "${IVNP_STREAM_LOAD_RATE:-65536}" --stream-load-window "${IVNP_STREAM_LOAD_WINDOW:-5s}"
)
if [ -n "$SCENARIO" ]; then
    RUNNER_ARGS+=(--scenario "$SCENARIO")
fi
if [ "$SCOPE" = public ]; then
    RUNNER_ARGS+=(--public-evidence "$PUBLIC_EVIDENCE" --public-probe-key "$PUBLIC_PROBE_KEY" --public-host "$PUBLIC_IP")
fi
if [ "$MODE" = smoke ]; then
    RUNNER_ARGS+=(--duration "$SMOKE_DURATION" --probe-interval "${IVNP_SMOKE_PROBE_INTERVAL:-10s}" --sample-interval "${IVNP_SMOKE_SAMPLE_INTERVAL:-10s}")
fi
phase "starting ${MODE}/${SCOPE}${SCENARIO:+/$SCENARIO} traffic runner with all four routers concurrent"
"$WORKDIR/ivnp-soak" "${RUNNER_ARGS[@]}"
