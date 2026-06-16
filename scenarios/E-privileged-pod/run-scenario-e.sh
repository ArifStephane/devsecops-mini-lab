#!/usr/bin/env bash
# =============================================================================
# run-scenario-e.sh — Scénario E : Pod avec configuration insecure
#
# Hypothèse testée : H3
# MITRE ATT&CK    : T1611 — Privilege Escalation via Escape to Host
#
# Ce script teste trois configurations dangereuses :
#   E1 — securityContext.privileged: true
#   E2 — hostPID: true
#   E3 — montage de /var/run/docker.sock
# Chacune doit être rejetée par Kyverno à l'admission.
# =============================================================================

set -euo pipefail
source "$(dirname "$0")/../../scripts/lib/kpi-utils.sh"

SCENARIO="E"
NAMESPACE="app"
RESULTS_FILE="../../scripts/results/scenario-e-$(date +%Y%m%d-%H%M%S).json"

log_scenario "=== SCÉNARIO E : Configuration insecure (T1611) ==="

declare -A RESULTS

# ---------------------------------------------------------------------------
# Fonction générique de test d'admission
# ---------------------------------------------------------------------------
test_admission() {
    local name="$1"
    local manifest_file="$2"
    local description="$3"

    log_step "[${name}] Test : ${description}"
    T_START=$(date +%s%3N)
    RESULT=$(kubectl apply -f "${manifest_file}" -n "${NAMESPACE}" 2>&1 || true)
    T_END=$(date +%s%3N)
    DURATION=$(( T_END - T_START ))

    if echo "${RESULT}" | grep -qiE "blocked|denied|policy|admission"; then
        log_ok "✓ [${name}] REJETÉ par Kyverno en ${DURATION} ms"
        RESULTS["${name}"]="REJECTED:${DURATION}"
    else
        log_err "✗ [${name}] AUTORISÉ (inattendu) — ${RESULT}"
        RESULTS["${name}"]="ALLOWED:${DURATION}"
        # Nettoyage immédiat si le pod a été créé
        kubectl delete -f "${manifest_file}" -n "${NAMESPACE}" --force 2>/dev/null || true
    fi
}

# ---------------------------------------------------------------------------
# E1 : Pod privileged
# ---------------------------------------------------------------------------
cat > /tmp/pod-privileged.yaml <<'MANIFEST'
apiVersion: v1
kind: Pod
metadata:
  name: test-privileged
  namespace: app
  labels:
    scenario: E
    sub: E1
spec:
  containers:
    - name: privileged-container
      image: alpine:3.19
      command: ["sleep", "3600"]
      securityContext:
        privileged: true
  restartPolicy: Never
MANIFEST
test_admission "E1" "/tmp/pod-privileged.yaml" "securityContext.privileged: true"

# ---------------------------------------------------------------------------
# E2 : Pod hostPID
# ---------------------------------------------------------------------------
cat > /tmp/pod-hostpid.yaml <<'MANIFEST'
apiVersion: v1
kind: Pod
metadata:
  name: test-hostpid
  namespace: app
  labels:
    scenario: E
    sub: E2
spec:
  hostPID: true
  containers:
    - name: hostpid-container
      image: alpine:3.19
      command: ["sleep", "3600"]
  restartPolicy: Never
MANIFEST
test_admission "E2" "/tmp/pod-hostpid.yaml" "hostPID: true"

# ---------------------------------------------------------------------------
# E3 : Montage de /var/run/docker.sock
# ---------------------------------------------------------------------------
cat > /tmp/pod-dockersock.yaml <<'MANIFEST'
apiVersion: v1
kind: Pod
metadata:
  name: test-dockersock
  namespace: app
  labels:
    scenario: E
    sub: E3
spec:
  containers:
    - name: dockersock-container
      image: alpine:3.19
      command: ["sleep", "3600"]
      volumeMounts:
        - name: docker-sock
          mountPath: /var/run/docker.sock
  volumes:
    - name: docker-sock
      hostPath:
        path: /var/run/docker.sock
        type: Socket
  restartPolicy: Never
MANIFEST
test_admission "E3" "/tmp/pod-dockersock.yaml" "montage /var/run/docker.sock"

# ---------------------------------------------------------------------------
# Export des résultats
# ---------------------------------------------------------------------------
mkdir -p "$(dirname "${RESULTS_FILE}")"

E1_STATUS=$(echo "${RESULTS[E1]}" | cut -d: -f1)
E1_DURATION=$(echo "${RESULTS[E1]}" | cut -d: -f2)
E2_STATUS=$(echo "${RESULTS[E2]}" | cut -d: -f1)
E2_DURATION=$(echo "${RESULTS[E2]}" | cut -d: -f2)
E3_STATUS=$(echo "${RESULTS[E3]}" | cut -d: -f1)
E3_DURATION=$(echo "${RESULTS[E3]}" | cut -d: -f2)

ALL_REJECTED=false
[ "${E1_STATUS}" = "REJECTED" ] && [ "${E2_STATUS}" = "REJECTED" ] && [ "${E3_STATUS}" = "REJECTED" ] && ALL_REJECTED=true

cat > "${RESULTS_FILE}" <<EOF
{
  "scenario": "${SCENARIO}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mitre_technique": "T1611",
  "tests": {
    "E1_privileged": {
      "description": "securityContext.privileged: true",
      "admission_status": "${E1_STATUS}",
      "admission_duration_ms": ${E1_DURATION}
    },
    "E2_hostPID": {
      "description": "hostPID: true",
      "admission_status": "${E2_STATUS}",
      "admission_duration_ms": ${E2_DURATION}
    },
    "E3_docker_sock": {
      "description": "montage /var/run/docker.sock",
      "admission_status": "${E3_STATUS}",
      "admission_duration_ms": ${E3_DURATION}
    }
  },
  "all_rejected": ${ALL_REJECTED},
  "hypothesis": "H3"
}
EOF

if [ "${ALL_REJECTED}" = true ]; then
    log_ok "✓ SCÉNARIO E : Toutes les configurations insecure rejetées — H3 partiellement validée"
else
    log_err "✗ SCÉNARIO E : Certaines configurations insecure ont été acceptées"
fi

log_ok "Résultats exportés → ${RESULTS_FILE}"
log_scenario "=== FIN SCÉNARIO E ==="
