#!/usr/bin/env bash
# =============================================================================
# run-scenario-c.sh — Scénario C : Shell interactif dans un pod
#
# Hypothèse testée : H2
# MITRE ATT&CK    : T1609 — Container Administration Command
#                   T1610 — Deploy Container
#
# Ce script :
# 1. Identifie un pod applicatif en cours d'exécution
# 2. Lance kubectl exec -it (simulation d'accès shell interactif)
# 3. Mesure le MTTD (Mean Time to Detect) — délai avant alerte Falco
# 4. Vérifie que l'alerte remonte dans Loki
# =============================================================================

set -euo pipefail
source "$(dirname "$0")/../../scripts/lib/kpi-utils.sh"

SCENARIO="C"
NAMESPACE="app"
RESULTS_FILE="${RESULTS_DIR}/scenario-c-$(date +%Y%m%d-%H%M%S).json"
FALCO_ALERT_TIMEOUT=30  # secondes d'attente pour l'alerte Falco

log_scenario "=== SCÉNARIO C : Shell interactif dans pod (T1609) ==="

# ---------------------------------------------------------------------------
# Étape 1 : Identification d'un pod cible
# ---------------------------------------------------------------------------
log_step "Identification d'un pod applicatif..."
POD_NAME=$(kubectl get pods -n "${NAMESPACE}" \
    -l app=target-api \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}')

if [ -z "${POD_NAME}" ]; then
    log_err "Aucun pod applicatif en cours d'exécution dans le namespace ${NAMESPACE}"
    exit 1
fi
log_ok "Pod cible : ${POD_NAME}"

# ---------------------------------------------------------------------------
# Étape 2 : Nettoyage des alertes Falco existantes (baseline propre)
# ---------------------------------------------------------------------------
log_step "Initialisation — enregistrement du timestamp de référence..."
T_REFERENCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
log_ok "Timestamp de référence : ${T_REFERENCE}"

# ---------------------------------------------------------------------------
# Étape 3 : Exécution du shell interactif (action malveillante simulée)
# ---------------------------------------------------------------------------
log_step "Lancement du kubectl exec (simulation d'intrusion)..."
T_ACTION=$(date_ms)

# Exécution non-interactive (compatible environnement automatisé)
# En laboratoire réel : kubectl exec -it "${POD_NAME}" -n "${NAMESPACE}" -- /bin/sh
kubectl exec "${POD_NAME}" -n "${NAMESPACE}" -- /bin/sh -c "echo 'Scenario C - shell exec simulation'" 2>&1 || true

T_ACTION_END=$(date_ms)
log_ok "Action exécutée (t=${T_ACTION} ms)"

# ---------------------------------------------------------------------------
# Étape 4 : Attente et mesure de l'alerte Falco
# ---------------------------------------------------------------------------
log_step "Attente de l'alerte Falco (timeout=${FALCO_ALERT_TIMEOUT}s)..."

ALERT_DETECTED=false
T_DETECT=""

# Falco tourne en standalone Docker hors k3d sur macOS/Docker Desktop
falco_logs() {
    if docker ps --filter "name=falco-standalone" --filter "status=running" \
            --format "{{.Names}}" 2>/dev/null | grep -q "falco-standalone"; then
        docker logs falco-standalone 2>&1
    else
        # Fallback : pod Falco dans k3d
        local pod
        pod=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
        [ -n "${pod}" ] && kubectl logs "${pod}" -n falco 2>/dev/null || true
    fi
}

for i in $(seq 1 "${FALCO_ALERT_TIMEOUT}"); do
    if falco_logs | grep -qE "Shell exécuté|Shell spawné|Terminal shell|T1609|shell.*conteneur|conteneur.*shell|container_exec"; then
        T_DETECT=$(date_ms)
        MTTD=$(( T_DETECT - T_ACTION ))
        ALERT_DETECTED=true
        log_ok "✓ ALERTE DÉTECTÉE après ${i}s — MTTD = ${MTTD} ms"
        break
    fi
    sleep 1
done

if [ "${ALERT_DETECTED}" = false ]; then
    log_err "✗ ALERTE NON DÉTECTÉE dans les ${FALCO_ALERT_TIMEOUT}s impartis"
    MTTD=-1
fi

# ---------------------------------------------------------------------------
# Étape 5 : Vérification dans Loki
# ---------------------------------------------------------------------------
log_step "Vérification du routage de l'alerte vers Loki..."
LOKI_CHECK=$(kubectl exec -n monitoring \
    "$(kubectl get pods -n monitoring -l app=loki -o jsonpath='{.items[0].metadata.name}')" \
    -- wget -qO- "http://localhost:3100/loki/api/v1/query?query={app=\"falco\"}&limit=5" \
    2>/dev/null || echo "loki-unavailable")

if echo "${LOKI_CHECK}" | grep -q "Terminal shell\|Shell interactif"; then
    log_ok "✓ Alerte routée vers Loki"
    LOKI_ROUTING="OK"
else
    log_warn "⚠ Alerte non confirmée dans Loki (vérifier Falcosidekick)"
    LOKI_ROUTING="UNCONFIRMED"
fi

# ---------------------------------------------------------------------------
# Étape 6 : Export des résultats
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "${RESULTS_FILE}")"
cat > "${RESULTS_FILE}" <<EOF
{
  "scenario": "${SCENARIO}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "pod_targeted": "${POD_NAME}",
  "mitre_technique": "T1609",
  "action_timestamp_ms": ${T_ACTION},
  "detection": {
    "alert_detected": ${ALERT_DETECTED},
    "mttd_ms": ${MTTD},
    "mttd_seconds": $(echo "scale=2; ${MTTD} / 1000" | bc 2>/dev/null || echo "null"),
    "sla_met": $([ "${MTTD}" -gt 0 ] && [ "${MTTD}" -le 5000 ] && echo "true" || echo "false"),
    "loki_routing": "${LOKI_ROUTING}"
  },
  "hypothesis": "H2"
}
EOF

log_ok "Résultats exportés → ${RESULTS_FILE}"
log_scenario "=== FIN SCÉNARIO C ==="
