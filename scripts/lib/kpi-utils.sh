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

# Répertoire de résultats
RESULTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../results" && pwd)"
mkdir -p "${RESULTS_DIR}"
