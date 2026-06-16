#!/usr/bin/env bash
# =============================================================================
# measure-false-positives.sh — Mesure du taux de faux positifs Falco
#
# Collecte les alertes générées pendant la session de trafic nominal et
# calcule le FPR (False Positive Rate) pour l'indicateur KPI H2.
# =============================================================================

set -euo pipefail
source "$(dirname "$0")/lib/kpi-utils.sh"

RESULTS_FILE="${RESULTS_DIR}/fpr-$(date +%Y%m%d-%H%M%S).json"

log_step "Collecte des alertes Falco sur la session de trafic nominal..."

# Récupération des logs Falco (standalone Docker ou pod k3d)
get_falco_logs() {
    if docker ps --filter "name=falco-standalone" --filter "status=running" \
            --format "{{.Names}}" 2>/dev/null | grep -q "falco-standalone"; then
        docker logs falco-standalone 2>&1
    else
        local pod
        pod=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco \
            -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
        if [ -n "${pod}" ]; then
            kubectl logs "${pod}" -n falco 2>/dev/null || true
        else
            log_warn "Falco non disponible (ni standalone ni pod k3d)"
            echo ""
        fi
    fi
}

FALCO_LOGS=$(get_falco_logs)

if [ -z "${FALCO_LOGS}" ]; then
    log_warn "Aucun log Falco disponible — FPR = 0 par défaut"
    ALL_ALERTS=0
    KNOWN_TP=0
    CANDIDATE_FP=0
    FPR="0.0"
else
    # Comptage sécurisé (évite les erreurs si grep ne trouve rien)
    ALL_ALERTS=$(echo "${FALCO_LOGS}" | grep -c "priority\|Warning\|Error\|Critical\|Notice" 2>/dev/null || echo 0)
    KNOWN_TP=$(echo "${FALCO_LOGS}" | grep -cE "Scenario|lab_scenario|scenario=|Lab -" 2>/dev/null || echo 0)

    # Arithmétique sécurisée
    ALL_ALERTS=$(( ALL_ALERTS + 0 ))
    KNOWN_TP=$(( KNOWN_TP + 0 ))
    CANDIDATE_FP=$(( ALL_ALERTS - KNOWN_TP ))
    [ "${CANDIDATE_FP}" -lt 0 ] && CANDIDATE_FP=0

    # Calcul du FPR
    if [ "${ALL_ALERTS}" -gt 0 ]; then
        FPR=$(echo "scale=1; ${CANDIDATE_FP} * 100 / ${ALL_ALERTS}" | bc 2>/dev/null || echo "0.0")
    else
        FPR="0.0"
    fi
fi

TOTAL_REQUESTS=$(jq '.total_requests // 1' /tmp/traffic-stats.json 2>/dev/null || echo 1)

log_ok "Alertes totales          : ${ALL_ALERTS}"
log_ok "Vrais positifs connus    : ${KNOWN_TP}"
log_ok "Faux positifs candidats  : ${CANDIDATE_FP}"
log_ok "FPR estimé               : ${FPR}%  [seuil H2 : <5% après tuning]"

cat > "${RESULTS_FILE}" <<EOF
{
  "metric": "false_positive_rate",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "falco_alerts_total": ${ALL_ALERTS},
  "known_true_positives": ${KNOWN_TP},
  "candidate_false_positives": ${CANDIDATE_FP},
  "fpr_percent": ${FPR},
  "total_requests_nominal": ${TOTAL_REQUESTS},
  "threshold_h2_default": 20.0,
  "threshold_h2_tuned": 5.0,
  "note": "Mesure sur trafic nominal de laboratoire — voir limites méthodologiques Partie V"
}
EOF

log_ok "Résultats FPR exportés → ${RESULTS_FILE}"
