#!/usr/bin/env bash
# =============================================================================
# run-scenario-a.sh — Scénario A : Déploiement d'une image vulnérable
#
# Hypothèse testée : H1
# MITRE ATT&CK    : T1190 — Exploit Public-Facing Application
#
# Ce script :
# 1. Construit une image embarquant Log4j 2.14.1 (CVE-2021-44228, CVSS 10.0)
# 2. La scanne avec Trivy
# 3. Tente de la déployer dans le cluster (doit être bloquée)
# 4. Mesure et enregistre les KPI
# =============================================================================

set -euo pipefail
source "$(dirname "$0")/../../scripts/lib/kpi-utils.sh"

SCENARIO="A"
SCENARIO_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="target-api:vulnerable-log4shell"
RESULTS_FILE="${RESULTS_DIR}/scenario-a-$(date +%Y%m%d-%H%M%S).json"

log_scenario "=== SCÉNARIO A : Image vulnérable (CVE-2021-44228) ==="

# ---------------------------------------------------------------------------
# Étape 1 : Build de l'image vulnérable
# ---------------------------------------------------------------------------
log_step "Build de l'image vulnérable..."
T_BUILD_START=$(date_ms)
cd "${SCENARIO_DIR}"
docker build -f Dockerfile.vulnerable -t "${IMAGE_NAME}" . 2>&1
T_BUILD_END=$(date_ms)
log_ok "Image construite en $(( T_BUILD_END - T_BUILD_START )) ms"

# ---------------------------------------------------------------------------
# Étape 2 : Scan Trivy
# ---------------------------------------------------------------------------
log_step "Scan Trivy de l'image..."
T_SCAN_START=$(date_ms)

trivy image \
    --format json \
    --severity CRITICAL,HIGH \
    --output /tmp/trivy-scenario-a.json \
    "${IMAGE_NAME}" || true  # Ne pas échouer, capturer le résultat

T_SCAN_END=$(date_ms)
SCAN_DURATION=$(( T_SCAN_END - T_SCAN_START ))

# Extraction des KPI depuis le résultat Trivy
VULN_CRITICAL=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="CRITICAL")] | length' /tmp/trivy-scenario-a.json)
VULN_HIGH=$(jq '[.Results[].Vulnerabilities[]? | select(.Severity=="HIGH")] | length' /tmp/trivy-scenario-a.json)
LOG4SHELL_DETECTED=$(jq 'any(.Results[].Vulnerabilities[]?; .VulnerabilityID == "CVE-2021-44228")' /tmp/trivy-scenario-a.json)

log_ok "Scan terminé en ${SCAN_DURATION} ms"
log_ok "Vulnérabilités CRITICAL : ${VULN_CRITICAL}"
log_ok "Vulnérabilités HIGH     : ${VULN_HIGH}"
log_ok "CVE-2021-44228 détectée : ${LOG4SHELL_DETECTED}"

# Validation H1 : la CVE doit être détectée
if [ "${LOG4SHELL_DETECTED}" = "true" ]; then
    log_ok "✓ DÉTECTION RÉUSSIE — CVE-2021-44228 identifiée par Trivy (CVSS 10.0)"
    DETECTION_STATUS="DETECTED"
else
    log_err "✗ DÉTECTION ÉCHOUÉE — CVE-2021-44228 non détectée"
    DETECTION_STATUS="MISSED"
fi

# ---------------------------------------------------------------------------
# Étape 3 : Tentative de déploiement (doit être bloquée)
# ---------------------------------------------------------------------------
log_step "Tentative de déploiement dans le cluster..."

# Import de l'image dans k3d
k3d image import "${IMAGE_NAME}" -c devsecops-lab

# Application du manifest de déploiement vulnérable
T_ADMIT_START=$(date_ms)
ADMIT_RESULT=$(kubectl apply -f "${SCENARIO_DIR}/pod-vulnerable.yaml" --namespace app 2>&1 || true)
T_ADMIT_END=$(date_ms)
ADMIT_DURATION=$(( T_ADMIT_END - T_ADMIT_START ))

if echo "${ADMIT_RESULT}" | grep -q "blocked by policy"; then
    log_ok "✓ ADMISSION BLOQUÉE par Kyverno en ${ADMIT_DURATION} ms"
    log_ok "  Message : ${ADMIT_RESULT}"
    ADMISSION_STATUS="BLOCKED"
elif echo "${ADMIT_RESULT}" | grep -q "image signature"; then
    log_ok "✓ ADMISSION BLOQUÉE par vérification de signature en ${ADMIT_DURATION} ms"
    ADMISSION_STATUS="BLOCKED_UNSIGNED"
else
    log_err "✗ ADMISSION AUTORISÉE (inattendu) — ${ADMIT_RESULT}"
    ADMISSION_STATUS="ALLOWED"
fi

# ---------------------------------------------------------------------------
# Étape 4 : Export des résultats
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "${RESULTS_FILE}")"
cat > "${RESULTS_FILE}" <<EOF
{
  "scenario": "${SCENARIO}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "image": "${IMAGE_NAME}",
  "cve_tested": "CVE-2021-44228",
  "cvss_score": 10.0,
  "trivy_scan": {
    "duration_ms": ${SCAN_DURATION},
    "vulnerabilities_critical": ${VULN_CRITICAL},
    "vulnerabilities_high": ${VULN_HIGH},
    "log4shell_detected": ${LOG4SHELL_DETECTED},
    "detection_status": "${DETECTION_STATUS}"
  },
  "admission": {
    "duration_ms": ${ADMIT_DURATION},
    "status": "${ADMISSION_STATUS}"
  },
  "hypothesis": "H1"
}
EOF

log_ok "Résultats exportés → ${RESULTS_FILE}"
log_scenario "=== FIN SCÉNARIO A ==="
