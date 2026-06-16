#!/usr/bin/env bash
# =============================================================================
# run-scenario-b.sh — Scénario B : Déploiement d'une image non signée
#
# Hypothèse testée : H3
# MITRE ATT&CK    : T1195 — Supply Chain Compromise
#
# Ce script :
# 1. Build une image légitime SANS la signer avec Cosign
# 2. La pousse directement vers le registre (bypass du pipeline)
# 3. Tente de la déployer — doit être rejetée par Kyverno (verifyImages)
# 4. Mesure la latence de décision d'admission et enregistre les KPI
# =============================================================================

set -euo pipefail
source "$(dirname "$0")/../../scripts/lib/kpi-utils.sh"

SCENARIO="B"
REGISTRY="${REGISTRY:-ghcr.io}"
# GHCR exige un repo en minuscules
IMAGE_REPO="${IMAGE_REPO:-arifstephane/devsecops-mini-lab/target-api}"
IMAGE_TAG="unsigned-$(date +%s)"
FULL_IMAGE="${REGISTRY}/${IMAGE_REPO}:${IMAGE_TAG}"
RESULTS_FILE="${RESULTS_DIR}/scenario-b-$(date +%Y%m%d-%H%M%S).json"

log_scenario "=== SCÉNARIO B : Image non signée (Supply Chain Compromise) ==="

# ---------------------------------------------------------------------------
# Étape 1 : Build de l'image sans sécurité supplémentaire
# ---------------------------------------------------------------------------
log_step "Build de l'image légitime (sans signature)..."
cd "$(dirname "$0")/../../app"
docker build -t "${FULL_IMAGE}" .
log_ok "Image construite : ${FULL_IMAGE}"

# ---------------------------------------------------------------------------
# Étape 2 : Import direct dans k3d (bypass du pipeline — pas de signature)
# Pour le lab local, on importe sans passer par GHCR (push optionnel)
# ---------------------------------------------------------------------------
log_step "Import de l'image dans k3d (sans signature Cosign)..."
k3d image import "${FULL_IMAGE}" --cluster devsecops-lab 2>/dev/null || \
    log_warn "Import k3d optionnel — l'admission control sera testé via le nom d'image GHCR"
log_ok "Image disponible localement : ${FULL_IMAGE}"

# Vérification : aucune attestation de signature ne doit exister
if cosign verify "${FULL_IMAGE}" \
    --certificate-identity-regexp ".*" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    2>/dev/null; then
    log_err "✗ L'image est signée (inattendu pour ce scénario)"
    SIGNATURE_STATUS="SIGNED"
else
    log_ok "✓ Aucune signature présente — scénario conforme"
    SIGNATURE_STATUS="UNSIGNED"
fi

# ---------------------------------------------------------------------------
# Étape 3 : Tentative de déploiement (doit être bloquée par Kyverno)
# ---------------------------------------------------------------------------
log_step "Tentative de déploiement de l'image non signée..."

# Passage temporaire en Enforce pour tester le blocage
kubectl patch clusterpolicy verify-image-signature \
    --type=merge \
    -p '{"spec":{"validationFailureAction":"Enforce","rules":[{"name":"check-image-signature","verifyImages":[{"imageReferences":["ghcr.io/*/target-api*"],"mutateDigest":true,"verifyDigest":true,"required":true,"attestors":[{"count":1,"entries":[{"keyless":{"subject":"https://github.com/ArifStephane/devsecops-mini-lab/.github/workflows/pipeline.yml@refs/heads/main","issuer":"https://token.actions.githubusercontent.com","rekor":{"url":"https://rekor.sigstore.dev"}}}]}]}]}]}}' \
    2>/dev/null || log_warn "Patch verifyImages impossible — test en mode Audit"

sleep 2

# Génération du manifest de déploiement avec l'image non signée
cat > /tmp/pod-unsigned.yaml <<MANIFEST
apiVersion: v1
kind: Pod
metadata:
  name: test-unsigned-image
  namespace: app
  labels:
    scenario: B
spec:
  containers:
    - name: target-api
      image: "${FULL_IMAGE}"
  restartPolicy: Never
MANIFEST

T_ADMIT_START=$(date_ms)
ADMIT_RESULT=$(kubectl apply -f /tmp/pod-unsigned.yaml 2>&1 || true)
T_ADMIT_END=$(date_ms)
ADMIT_DURATION=$(( T_ADMIT_END - T_ADMIT_START ))

if echo "${ADMIT_RESULT}" | grep -qiE "blocked|denied|verifyImages|signature"; then
    log_ok "✓ DÉPLOIEMENT REJETÉ par Kyverno en ${ADMIT_DURATION} ms"
    log_ok "  Message : ${ADMIT_RESULT}"
    ADMISSION_STATUS="REJECTED"
    # Extraction du message de rejet pour le résultat (grep -oE compatible macOS)
    REJECT_REASON=$(echo "${ADMIT_RESULT}" | grep -oE 'error.*' | head -1 || echo "${ADMIT_RESULT}")
else
    log_err "✗ DÉPLOIEMENT AUTORISÉ (inattendu) — la politique verifyImages n'a pas fonctionné"
    ADMISSION_STATUS="ALLOWED"
    REJECT_REASON=""
fi

# Nettoyage
kubectl delete pod test-unsigned-image --namespace app 2>/dev/null || true

# Repasser en Audit après le test
kubectl patch clusterpolicy verify-image-signature \
    --type=merge \
    -p '{"spec":{"validationFailureAction":"Audit","rules":[{"name":"check-image-signature","verifyImages":[{"imageReferences":["ghcr.io/*/target-api*"],"mutateDigest":false,"verifyDigest":false,"required":false,"attestors":[{"count":1,"entries":[{"keyless":{"subject":"https://github.com/ArifStephane/devsecops-mini-lab/.github/workflows/pipeline.yml@refs/heads/main","issuer":"https://token.actions.githubusercontent.com","rekor":{"url":"https://rekor.sigstore.dev"}}}]}]}]}]}}' \
    2>/dev/null || true

# ---------------------------------------------------------------------------
# Étape 4 : Export des résultats
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "${RESULTS_FILE}")"
cat > "${RESULTS_FILE}" <<EOF
{
  "scenario": "${SCENARIO}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "image": "${FULL_IMAGE}",
  "signature_status": "${SIGNATURE_STATUS}",
  "admission": {
    "duration_ms": ${ADMIT_DURATION},
    "status": "${ADMISSION_STATUS}",
    "reject_reason": $(echo "${REJECT_REASON}" | jq -Rs .)
  },
  "hypothesis": "H3"
}
EOF

log_ok "Résultats exportés → ${RESULTS_FILE}"
log_scenario "=== FIN SCÉNARIO B ==="
