#!/usr/bin/env bash
# =============================================================================
# generate-nominal-traffic.sh — Générateur de trafic applicatif nominal
#
# Simule l'activité légitime de l'application pour mesurer le taux de faux
# positifs Falco sur un trafic non-malveillant.
# Usage : bash scripts/generate-nominal-traffic.sh [DURATION_SECONDS]
# =============================================================================

DURATION="${1:-300}"  # 5 min par défaut (300s en lab, 86400s = 24h en prod)
APP_URL="${APP_URL:-http://localhost:8000}"

echo "[trafic] Génération de trafic nominal pendant ${DURATION}s..."
END_TIME=$(( $(date +%s) + DURATION ))

# Compteurs
REQUESTS=0
ERRORS=0

while [ "$(date +%s)" -lt "${END_TIME}" ]; do
    # GET /health
    curl -sf "${APP_URL}/health" > /dev/null 2>&1 && REQUESTS=$((REQUESTS + 1)) || ERRORS=$((ERRORS + 1))

    # POST /items
    curl -sf -X POST "${APP_URL}/items" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"item-$(date +%s)\", \"description\": \"test\"}" \
        > /dev/null 2>&1 && REQUESTS=$((REQUESTS + 1)) || ERRORS=$((ERRORS + 1))

    # GET /items/1
    curl -sf "${APP_URL}/items/1" > /dev/null 2>&1 && REQUESTS=$((REQUESTS + 1)) || ERRORS=$((ERRORS + 1))

    sleep 2
done

echo "[trafic] Terminé — ${REQUESTS} requêtes, ${ERRORS} erreurs"
echo "{\"total_requests\": ${REQUESTS}, \"errors\": ${ERRORS}, \"duration_s\": ${DURATION}}" \
    > /tmp/traffic-stats.json
