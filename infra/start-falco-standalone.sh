#!/usr/bin/env bash
# =============================================================================
# start-falco-standalone.sh
# Lance Falco en mode standalone (hors k3d) avec les règles personnalisées
# et routage vers Falcosidekick.
#
# Contexte : macOS / Docker Desktop — le kernel linuxkit ne permet pas
# d'exécuter Falco DANS k3d (BPF ring buffer inaccessible aux conteneurs
# de second niveau). Falco est donc lancé comme conteneur Docker privilégié
# avec accès direct à la VM linuxkit et détecte les syscalls de TOUS les
# conteneurs k3d via --pid=host.
#
# Usage : bash infra/start-falco-standalone.sh [start|stop|status|logs]
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

CONTAINER_NAME="falco-standalone"
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CUSTOM_RULES="${LAB_ROOT}/falco/custom-rules.yaml"

# Port-forward Falcosidekick si disponible
FALCOSIDEKICK_URL="http://host.docker.internal:2801"

ACTION="${1:-start}"

case "${ACTION}" in
# ---------------------------------------------------------------------------
start)
    log "Arrêt d'une éventuelle instance précédente..."
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

    # Port-forward Falcosidekick en arrière-plan
    log "Ouverture du tunnel Falcosidekick (port 2801)..."
    kubectl port-forward svc/falco-falcosidekick 2801:2801 -n falco \
        > /tmp/falcosidekick-pf.log 2>&1 &
    PF_PID=$!
    echo "${PF_PID}" > /tmp/falcosidekick-pf.pid
    sleep 2

    log "Démarrage de Falco standalone..."
    docker run -d \
        --name "${CONTAINER_NAME}" \
        --privileged \
        --pid=host \
        --restart=unless-stopped \
        -e HOST_ROOT=/host \
        -e FALCO_BPF_PROBE="" \
        -v /proc:/host/proc:ro \
        -v /var/run/docker.sock:/host/var/run/docker.sock \
        -v "${CUSTOM_RULES}":/etc/falco/rules.d/custom-rules.yaml:ro \
        falcosecurity/falco:latest \
        falco \
            --option "json_output=true" \
            --option "json_include_output_property=true" \
            --option "http_output.enabled=true" \
            --option "http_output.url=${FALCOSIDEKICK_URL}" \
            --option "stdout_output.enabled=true"

    sleep 5
    if docker ps --filter "name=${CONTAINER_NAME}" --filter "status=running" \
            --format "{{.Names}}" | grep -q "${CONTAINER_NAME}"; then
        log "Falco standalone opérationnel ✓"
        log "Logs : docker logs -f ${CONTAINER_NAME}"
    else
        err "Falco a crashé — vérifier : docker logs ${CONTAINER_NAME}"
    fi
    ;;

# ---------------------------------------------------------------------------
stop)
    log "Arrêt de Falco standalone..."
    docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true
    if [ -f /tmp/falcosidekick-pf.pid ]; then
        kill "$(cat /tmp/falcosidekick-pf.pid)" 2>/dev/null || true
        rm -f /tmp/falcosidekick-pf.pid
    fi
    log "Arrêté."
    ;;

# ---------------------------------------------------------------------------
status)
    if docker ps --filter "name=${CONTAINER_NAME}" --filter "status=running" \
            --format "{{.Names}}" | grep -q "${CONTAINER_NAME}"; then
        log "Falco standalone est en cours d'exécution."
        docker stats "${CONTAINER_NAME}" --no-stream
    else
        warn "Falco standalone n'est PAS en cours d'exécution."
    fi
    ;;

# ---------------------------------------------------------------------------
logs)
    docker logs -f "${CONTAINER_NAME}"
    ;;

*)
    echo "Usage : $0 [start|stop|status|logs]"
    exit 1
    ;;
esac
