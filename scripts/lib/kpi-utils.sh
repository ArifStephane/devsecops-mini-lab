#!/usr/bin/env bash
# =============================================================================
# kpi-utils.sh — Bibliothèque de fonctions utilitaires pour les KPI
# Sourcé par tous les scripts de scénario et de mesure
# =============================================================================

# Couleurs
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log_scenario() { echo -e "\n${CYAN}[LAB]${NC} $1\n"; }
log_step()     { echo -e "${BLUE}[→]${NC} $1"; }
log_ok()       { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()     { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()      { echo -e "${RED}[✗]${NC} $1"; }

# Répertoire de résultats (chemin absolu, indépendant du répertoire d'appel)
_UTILS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${_UTILS_DIR}/../results"
mkdir -p "${RESULTS_DIR}"
RESULTS_DIR="$(cd "${RESULTS_DIR}" && pwd)"

# ---------------------------------------------------------------------------
# date_ms : timestamp en millisecondes, compatible macOS (BSD date)
# macOS date ne supporte pas %N → fallback python3 puis secondes×1000
# ---------------------------------------------------------------------------
date_ms() {
    if command -v gdate &>/dev/null; then
        gdate +%s%3N
    elif command -v python3 &>/dev/null; then
        python3 -c "import time; print(int(time.time() * 1000))"
    else
        echo "$(date +%s)000"
    fi
}
