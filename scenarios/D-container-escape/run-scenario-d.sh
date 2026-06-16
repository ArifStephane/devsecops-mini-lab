#!/usr/bin/env bash
# =============================================================================
# run-scenario-d.sh — Scénario D : Simulation d'évasion vers l'hôte
#
# Hypothèse testée : H2
# MITRE ATT&CK    : T1611 — Escape to Host
#
# Ce script simule deux techniques d'évasion contrôlées :
#   D1 — Lecture de /proc/1/root depuis un conteneur
#   D2 — Écriture dans un volume monté suspect (/tmp/hostmount)
# Mesure : Falco doit générer une alerte pour chaque technique.
# =============================================================================

set -euo pipefail
source "$(dirname "$0")/../../scripts/lib/kpi-utils.sh"

SCENARIO="D"
NAMESPACE="app"
RESULTS_FILE="../../scripts/results/scenario-d-$(date +%Y%m%d-%H%M%S).json"

log_scenario "=== SCÉNARIO D : Évasion vers l'hôte simulée (T1611) ==="

# ---------------------------------------------------------------------------
# Sous-scénario D1 : Tentative de lecture /proc/1/root
# ---------------------------------------------------------------------------
log_step "[D1] Déploiement d'un pod de test pour lecture /proc/1/root..."

cat <<'MANIFEST' | kubectl apply -f - -n "${NAMESPACE}"
apiVersion: v1
kind: Pod
metadata:
  name: escape-test-d1
  namespace: app
  labels:
    scenario: D
    sub: D1
spec:
  containers:
    - name: escape-test
      image: alpine:3.19
      command: ["sh", "-c", "cat /proc/1/root/etc/hostname 2>/dev/null || echo 'access-blocked'; sleep 3600"]
  restartPolicy: Never
MANIFEST

# Attente du démarrage du pod
kubectl wait --for=condition=ready pod/escape-test-d1 -n "${NAMESPACE}" --timeout=60s 2>/dev/null || true

T_ACTION_D1=$(date +%s%3N)
log_ok "[D1] Action exécutée — attente de l'alerte Falco..."

ALERT_D1=false
for i in $(seq 1 30); do
    FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    if kubectl logs "${FALCO_POD}" -n falco --since=35s 2>/dev/null | \
       grep -qE "proc/1/root|Accès.*hôte|T1611|container_escape"; then
        T_DETECT_D1=$(date +%s%3N)
        MTTD_D1=$(( T_DETECT_D1 - T_ACTION_D1 ))
        ALERT_D1=true
        log_ok "✓ [D1] Alerte détectée — MTTD = ${MTTD_D1} ms"
        break
    fi
    sleep 1
done

[ "${ALERT_D1}" = false ] && { log_err "✗ [D1] Alerte non détectée"; MTTD_D1=-1; }

# Nettoyage D1
kubectl delete pod escape-test-d1 -n "${NAMESPACE}" --force 2>/dev/null || true

# ---------------------------------------------------------------------------
# Sous-scénario D2 : Écriture suspecte (montage suspect simulé)
# ---------------------------------------------------------------------------
log_step "[D2] Déploiement d'un pod de test pour écriture dans /etc..."

# Note : ce pod sera bloqué par Kyverno si les règles deny-privileged sont actives
# Si Kyverno est désactivé (baseline), le pod démarre et Falco doit détecter l'écriture
cat <<'MANIFEST' | kubectl apply -f - -n "${NAMESPACE}" 2>&1 || true
apiVersion: v1
kind: Pod
metadata:
  name: escape-test-d2
  namespace: app
  labels:
    scenario: D
    sub: D2
spec:
  containers:
    - name: escape-test
      image: alpine:3.19
      command: ["sh", "-c", "echo 'escape-test' > /etc/escape-marker 2>/dev/null || echo 'write-blocked'; sleep 3600"]
      securityContext:
        readOnlyRootFilesystem: false
  restartPolicy: Never
MANIFEST

DEPLOY_D2_STATUS=$?
T_ACTION_D2=$(date +%s%3N)

if [ "${DEPLOY_D2_STATUS}" -ne 0 ]; then
    log_ok "[D2] Déploiement bloqué par Kyverno (comportement attendu en config shift-everywhere)"
    ALERT_D2=false
    MTTD_D2=-1
    D2_BLOCKED_BY_ADMISSION=true
else
    kubectl wait --for=condition=ready pod/escape-test-d2 -n "${NAMESPACE}" --timeout=60s 2>/dev/null || true
    D2_BLOCKED_BY_ADMISSION=false
    ALERT_D2=false
    for i in $(seq 1 30); do
        FALCO_POD=$(kubectl get pods -n falco -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
        if kubectl logs "${FALCO_POD}" -n falco --since=35s 2>/dev/null | \
           grep -qE "escape-marker|Écriture.*système|T1611"; then
            T_DETECT_D2=$(date +%s%3N)
            MTTD_D2=$(( T_DETECT_D2 - T_ACTION_D2 ))
            ALERT_D2=true
            log_ok "✓ [D2] Alerte détectée — MTTD = ${MTTD_D2} ms"
            break
        fi
        sleep 1
    done
    [ "${ALERT_D2}" = false ] && { log_err "✗ [D2] Alerte non détectée"; MTTD_D2=-1; }
    kubectl delete pod escape-test-d2 -n "${NAMESPACE}" --force 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Export des résultats
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "${RESULTS_FILE}")"
cat > "${RESULTS_FILE}" <<EOF
{
  "scenario": "${SCENARIO}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mitre_technique": "T1611",
  "sub_scenarios": {
    "D1_proc_access": {
      "alert_detected": ${ALERT_D1},
      "mttd_ms": ${MTTD_D1}
    },
    "D2_filesystem_write": {
      "blocked_by_admission": ${D2_BLOCKED_BY_ADMISSION:-false},
      "alert_detected": ${ALERT_D2},
      "mttd_ms": ${MTTD_D2:-null}
    }
  },
  "hypothesis": "H2"
}
EOF

log_ok "Résultats exportés → ${RESULTS_FILE}"
log_scenario "=== FIN SCÉNARIO D ==="
