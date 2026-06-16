#!/usr/bin/env bash
# =============================================================================
# run-all-scenarios.sh — Exécution séquentielle des 5 scénarios d'attaque
#
# Usage : bash scripts/run-all-scenarios.sh [--config CONFIGURATION]
# Configurations : shift-left | shift-everywhere | runtime-only
# =============================================================================

set -euo pipefail
source "$(dirname "$0")/lib/kpi-utils.sh"

CONFIG="${1:-shift-everywhere}"
LAB_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

log_scenario "=== EXÉCUTION COMPLÈTE — Configuration : ${CONFIG} ==="

# Rendre tous les scripts exécutables
find "${LAB_ROOT}/scenarios" -name "run-scenario-*.sh" -exec chmod +x {} \;

# ---------------------------------------------------------------------------
# Phase optionnelle : mesure du taux de faux positifs sur trafic nominal
# (24h en production ; réduit à 5 minutes pour validation du lab)
# ---------------------------------------------------------------------------
log_step "Lancement du générateur de trafic nominal (5 min)..."
nohup bash "${LAB_ROOT}/scripts/generate-nominal-traffic.sh" > /tmp/traffic-gen.log 2>&1 &
TRAFFIC_PID=$!
log_ok "Générateur de trafic lancé (PID=${TRAFFIC_PID})"

sleep 10  # Laisser le trafic s'établir avant les scénarios

# ---------------------------------------------------------------------------
# Exécution des scénarios
# ---------------------------------------------------------------------------
SCENARIOS=("A" "B" "C" "D" "E")
declare -A SCENARIO_STATUS

for S in "${SCENARIOS[@]}"; do
    log_step "--- Scénario ${S} ---"
    SCRIPT="${LAB_ROOT}/scenarios"

    case "${S}" in
        A) SCRIPT="${SCRIPT}/A-vulnerable-image/run-scenario-a.sh" ;;
        B) SCRIPT="${SCRIPT}/B-unsigned-image/run-scenario-b.sh" ;;
        C) SCRIPT="${SCRIPT}/C-shell-exec/run-scenario-c.sh" ;;
        D) SCRIPT="${SCRIPT}/D-container-escape/run-scenario-d.sh" ;;
        E) SCRIPT="${SCRIPT}/E-privileged-pod/run-scenario-e.sh" ;;
    esac

    if bash "${SCRIPT}" 2>&1 | tee "/tmp/scenario-${S}.log"; then
        SCENARIO_STATUS["${S}"]="OK"
        log_ok "Scénario ${S} terminé"
    else
        SCENARIO_STATUS["${S}"]="ERROR"
        log_err "Scénario ${S} en erreur — consulter /tmp/scenario-${S}.log"
    fi

    sleep 5  # Pause entre scénarios pour éviter les interférences
done

# ---------------------------------------------------------------------------
# Arrêt du générateur de trafic et mesure des faux positifs
# ---------------------------------------------------------------------------
log_step "Arrêt du générateur de trafic..."
kill "${TRAFFIC_PID}" 2>/dev/null || true
sleep 5

log_step "Collecte des alertes Falco sur trafic nominal (calcul FPR)..."
bash "${LAB_ROOT}/scripts/measure-false-positives.sh" || log_warn "Mesure FPR incomplète"

# ---------------------------------------------------------------------------
# Agrégation des KPI
# ---------------------------------------------------------------------------
log_step "Agrégation des KPI..."
bash "${LAB_ROOT}/scripts/collect-kpi.sh" "${CONFIG}"

log_scenario "=== FIN DE L'EXÉCUTION COMPLÈTE ==="
