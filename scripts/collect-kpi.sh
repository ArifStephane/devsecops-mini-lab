#!/usr/bin/env bash
# =============================================================================
# collect-kpi.sh — Collecte et agrégation de tous les KPI du mini-lab
#
# Usage : bash scripts/collect-kpi.sh [--config CONFIGURATION]
# Configurations : baseline | shift-left | shift-everywhere | runtime-only
#
# Ce script agrège les résultats des 5 scénarios et produit un rapport JSON
# global permettant de calculer les indicateurs du tableau KPI du protocole.
# =============================================================================

set -euo pipefail
source "$(dirname "$0")/lib/kpi-utils.sh"

CONFIG="${1:-shift-everywhere}"
REPORT_FILE="${RESULTS_DIR}/kpi-report-${CONFIG}-$(date +%Y%m%d-%H%M%S).json"

log_scenario "=== COLLECTE DES KPI — Configuration : ${CONFIG} ==="

# ---------------------------------------------------------------------------
# Collecte des fichiers de résultats des scénarios
# ---------------------------------------------------------------------------
collect_scenario_result() {
    local scenario="$1"
    local pattern="scenario-${scenario}-*.json"
    local latest

    latest=$(ls -t "${RESULTS_DIR}/${pattern}" 2>/dev/null | head -1)
    if [ -n "${latest}" ]; then
        cat "${latest}"
    else
        echo "{\"scenario\": \"${scenario}\", \"error\": \"no_results_found\"}"
    fi
}

RESULT_A=$(collect_scenario_result "a")
RESULT_B=$(collect_scenario_result "b")
RESULT_C=$(collect_scenario_result "c")
RESULT_D=$(collect_scenario_result "d")
RESULT_E=$(collect_scenario_result "e")

# ---------------------------------------------------------------------------
# Calcul du Taux de Détection (TPR — True Positive Rate)
# ---------------------------------------------------------------------------
log_step "Calcul du TPR (Taux de Détection)..."

DETECTED=0
TOTAL=5

# Scénario A : CVE détectée ?
[ "$(echo "${RESULT_A}" | jq -r '.trivy_scan.log4shell_detected // false')" = "true" ] && DETECTED=$((DETECTED + 1))

# Scénario B : Image non signée rejetée ?
[ "$(echo "${RESULT_B}" | jq -r '.admission.status // "UNKNOWN"')" != "ALLOWED" ] && DETECTED=$((DETECTED + 1))

# Scénario C : Shell exec détecté ?
[ "$(echo "${RESULT_C}" | jq -r '.detection.alert_detected // false')" = "true" ] && DETECTED=$((DETECTED + 1))

# Scénario D : Escape tentatif détecté ?
[ "$(echo "${RESULT_D}" | jq -r '.sub_scenarios.D1_proc_access.alert_detected // false')" = "true" ] && DETECTED=$((DETECTED + 1))

# Scénario E : Tous les pods insecures rejetés ?
[ "$(echo "${RESULT_E}" | jq -r '.all_rejected // false')" = "true" ] && DETECTED=$((DETECTED + 1))

TPR=$(echo "scale=1; ${DETECTED} * 100 / ${TOTAL}" | bc)
log_ok "TPR = ${TPR}% (${DETECTED}/${TOTAL} scénarios détectés)"

# ---------------------------------------------------------------------------
# Calcul du MTTD moyen (Scénarios C et D)
# ---------------------------------------------------------------------------
log_step "Calcul du MTTD moyen..."

MTTD_C=$(echo "${RESULT_C}" | jq '.detection.mttd_ms // -1')
MTTD_D=$(echo "${RESULT_D}" | jq '.sub_scenarios.D1_proc_access.mttd_ms // -1')

if [ "${MTTD_C}" -gt 0 ] && [ "${MTTD_D}" -gt 0 ]; then
    MTTD_AVG=$(( (MTTD_C + MTTD_D) / 2 ))
    MTTD_SECONDS=$(echo "scale=2; ${MTTD_AVG} / 1000" | bc)
    log_ok "MTTD moyen = ${MTTD_SECONDS}s"
elif [ "${MTTD_C}" -gt 0 ]; then
    MTTD_AVG="${MTTD_C}"
    MTTD_SECONDS=$(echo "scale=2; ${MTTD_AVG} / 1000" | bc)
    log_ok "MTTD (C uniquement) = ${MTTD_SECONDS}s"
else
    MTTD_AVG=-1
    MTTD_SECONDS="null"
    log_warn "MTTD non calculable (données insuffisantes)"
fi

# ---------------------------------------------------------------------------
# Collecte du surcoût pipeline (depuis les artefacts GitHub Actions)
# ---------------------------------------------------------------------------
log_step "Collecte des métriques pipeline..."

BASELINE_DURATION=$(ls -t "${RESULTS_DIR}"/baseline-metrics-*.json 2>/dev/null | head -1 | \
    xargs -I{} jq '.duration_seconds // null' {} 2>/dev/null || echo "null")

SECURED_DURATION=$(ls -t "${RESULTS_DIR}"/pipeline-metrics-*.json 2>/dev/null | head -1 | \
    xargs -I{} jq '.duration_seconds // null' {} 2>/dev/null || echo "null")

if [ "${BASELINE_DURATION}" != "null" ] && [ "${SECURED_DURATION}" != "null" ]; then
    PIPELINE_OVERHEAD=$(echo "scale=1; (${SECURED_DURATION} - ${BASELINE_DURATION}) * 100 / ${BASELINE_DURATION}" | bc)
    log_ok "Surcoût pipeline = ${PIPELINE_OVERHEAD}% (baseline=${BASELINE_DURATION}s, sécurisé=${SECURED_DURATION}s)"
else
    PIPELINE_OVERHEAD="null"
    log_warn "Données pipeline insuffisantes pour calculer le surcoût"
fi

# ---------------------------------------------------------------------------
# Couverture MITRE ATT&CK for Containers
# ---------------------------------------------------------------------------
log_step "Calcul de la couverture MITRE..."

# Techniques couvertes par les contrôles du mini-lab
MITRE_COVERED=("T1190" "T1195" "T1609" "T1610" "T1611" "T1053" "T1071")
MITRE_TOTAL_CONTAINERS=9  # Techniques principales de la matrice ATT&CK for Containers
MITRE_COVERAGE=$(echo "scale=1; ${#MITRE_COVERED[@]} * 100 / ${MITRE_TOTAL_CONTAINERS}" | bc)
log_ok "Couverture MITRE = ${MITRE_COVERAGE}% (${#MITRE_COVERED[@]}/${MITRE_TOTAL_CONTAINERS} techniques)"

# ---------------------------------------------------------------------------
# Génération du rapport JSON global
# ---------------------------------------------------------------------------
log_step "Génération du rapport KPI consolidé..."

cat > "${REPORT_FILE}" <<EOF
{
  "report_metadata": {
    "configuration": "${CONFIG}",
    "generated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "operator": "mini-lab v1.0"
  },
  "kpi": {
    "tpr_detection_rate": {
      "value": ${TPR},
      "unit": "%",
      "scenarios_detected": ${DETECTED},
      "scenarios_total": ${TOTAL},
      "threshold_h1": 80.0,
      "h1_validated": $([ "$(echo "${TPR} >= 80" | bc 2>/dev/null || echo 0)" = "1" ] && echo "true" || echo "false")
    },
    "mttd_mean": {
      "value_ms": ${MTTD_AVG},
      "value_seconds": ${MTTD_SECONDS},
      "unit": "ms",
      "sla_seconds": 5
    },
    "pipeline_overhead": {
      "value": ${PIPELINE_OVERHEAD},
      "unit": "%",
      "baseline_seconds": ${BASELINE_DURATION},
      "secured_seconds": ${SECURED_DURATION},
      "threshold_h1": 15.0
    },
    "mitre_coverage": {
      "value": ${MITRE_COVERAGE},
      "unit": "%",
      "techniques_covered": $(printf '%s\n' "${MITRE_COVERED[@]}" | jq -R . | jq -s .),
      "techniques_total": ${MITRE_TOTAL_CONTAINERS}
    }
  },
  "scenario_results": {
    "A": $(echo "${RESULT_A}"),
    "B": $(echo "${RESULT_B}"),
    "C": $(echo "${RESULT_C}"),
    "D": $(echo "${RESULT_D}"),
    "E": $(echo "${RESULT_E}")
  }
}
EOF

log_ok "Rapport KPI exporté → ${REPORT_FILE}"

# Affichage du résumé
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  RÉSUMÉ KPI — Configuration : ${CONFIG}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
printf "  %-35s %s\n" "Taux de détection (TPR):"      "${TPR}%  [seuil H1: ≥80%]"
printf "  %-35s %s\n" "MTTD moyen:"                   "${MTTD_SECONDS}s  [seuil H2: <5s]"
printf "  %-35s %s\n" "Surcoût pipeline:"             "${PIPELINE_OVERHEAD}%  [seuil H1: <15%]"
printf "  %-35s %s\n" "Couverture MITRE for Containers:" "${MITRE_COVERAGE}%"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
