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
FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

log_step "Collecte des alertes Falco sur la session de trafic nominal..."

if [ -z "${FALCO_POD}" ]; then
    log_err "Pod Falco introuvable"
    exit 1
fi

# Collecte de toutes les alertes de la dernière heure
ALL_ALERTS=$(kubectl logs "${FALCO_POD}" -n falco --since=1h 2>/dev/null | \
    grep -c "priority" || echo 0)

# Alertes issues des scénarios d'attaque (vrais positifs connus)
KNOWN_TP=$(kubectl logs "${FALCO_POD}" -n falco --since=1h 2>/dev/null | \
    grep -cE "Scenario|lab_scenario|scenario=" || echo 0)

# Alertes sur trafic nominal (faux positifs candidats)
CANDIDATE_FP=$(( ALL_ALERTS - KNOWN_TP ))
[ "${CANDIDATE_FP}" -lt 0 ] && CANDIDATE_FP=0

# Récupération des stats de trafic
TOTAL_REQUESTS=$(jq '.total_requests // 1' /tmp/traffic-stats.json 2>/dev/null || echo 1)

# Calcul du FPR (alertes FP / total alertes)
if [ "${ALL_ALERTS}" -gt 0 ]; then
    FPR=$(echo "scale=1; ${CANDIDATE_FP} * 100 / ${ALL_ALERTS}" | bc)
else
    FPR="0.0"
fi

FPR_PER_HOUR=$(echo "scale=2; ${CANDIDATE_FP}" | bc)

log_ok "Alertes totales : ${ALL_ALERTS}"
log_ok "Vrais positifs connus : ${KNOWN_TP}"
log_ok "Faux positifs candidats : ${CANDIDATE_FP}"
log_ok "FPR estimé : ${FPR}%  [seuil H2 : <5% après tuning]"

cat > "${RESULTS_FILE}" <<EOF
{
  "metric": "false_positive_rate",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "falco_alerts_total": ${ALL_ALERTS},
  "known_true_positives": ${KNOWN_TP},
  "candidate_false_positives": ${CANDIDATE_FP},
  "fpr_percent": ${FPR},
  "fp_per_hour": ${FPR_PER_HOUR},
  "total_requests_nominal": ${TOTAL_REQUESTS},
  "threshold_h2_default": 20.0,
  "threshold_h2_tuned": 5.0,
  "note": "Mesure sur trafic nominal de laboratoire — voir limites méthodologiques Partie V"
}
EOF

log_ok "Résultats FPR exportés → ${RESULTS_FILE}"
