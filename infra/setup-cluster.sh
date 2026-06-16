#!/usr/bin/env bash
# =============================================================================
# setup-cluster.sh — Installation complète du laboratoire DevSecOps
#
# Prérequis : Docker, kubectl, k3d, helm, cosign
# Usage     : bash infra/setup-cluster.sh
#
# Ce script exécute l'ensemble des étapes de la Phase 1 (Préparation)
# définie dans le protocole expérimental.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Couleurs pour les logs
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ---------------------------------------------------------------------------
# Vérification des prérequis
# ---------------------------------------------------------------------------
log "Vérification des prérequis..."
for cmd in docker kubectl k3d helm cosign; do
    command -v "$cmd" &>/dev/null || err "Commande manquante : $cmd"
    log "  ✓ $cmd : $(${cmd} version 2>/dev/null | head -1 || echo 'ok')"
done

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
CLUSTER_NAME="devsecops-lab"
KYVERNO_VERSION="3.2.0"
FALCO_VERSION="4.6.0"
FALCOSIDEKICK_VERSION="0.8.0"

# ---------------------------------------------------------------------------
# Étape 1 : Création du cluster k3d
# ---------------------------------------------------------------------------
log "Création du cluster k3d '${CLUSTER_NAME}'..."

if k3d cluster list | grep -q "${CLUSTER_NAME}"; then
    warn "Cluster '${CLUSTER_NAME}' déjà existant, suppression..."
    k3d cluster delete "${CLUSTER_NAME}"
fi

k3d cluster create "${CLUSTER_NAME}" \
    --config infra/k3d-config.yaml \
    --wait

kubectl cluster-info
log "Cluster créé avec succès."

# ---------------------------------------------------------------------------
# Étape 2 : Création des namespaces
# ---------------------------------------------------------------------------
log "Création des namespaces..."
kubectl apply -f infra/k8s/namespaces.yaml
kubectl get namespaces

# ---------------------------------------------------------------------------
# Étape 3 : Installation de Kyverno
# ---------------------------------------------------------------------------
log "Installation de Kyverno v${KYVERNO_VERSION}..."
helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
helm repo update

helm upgrade --install kyverno kyverno/kyverno \
    --namespace kyverno \
    --create-namespace \
    --version "${KYVERNO_VERSION}" \
    --timeout 10m \
    --set admissionController.replicas=1 \
    --set backgroundController.replicas=1 \
    --set cleanupController.replicas=1 \
    --set reportsController.replicas=1

sleep 10
kubectl wait --for=condition=ready pod \
    --selector='app.kubernetes.io/component=admission-controller' \
    --namespace kyverno \
    --timeout=120s || \
kubectl wait --for=condition=ready pod \
    --selector='app.kubernetes.io/instance=kyverno' \
    --namespace kyverno \
    --timeout=120s || true

log "Kyverno installé."

# ---------------------------------------------------------------------------
# Étape 4 : Application des politiques Kyverno
# ---------------------------------------------------------------------------
log "Application des politiques Kyverno..."
kubectl apply -f policies/kyverno/
kubectl get clusterpolicies
log "Politiques Kyverno appliquées."

# ---------------------------------------------------------------------------
# Étape 5 : Installation de Falco
# ---------------------------------------------------------------------------
log "Installation de Falco v${FALCO_VERSION}..."
helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update
helm repo update

helm upgrade --install falco falcosecurity/falco \
    --namespace falco \
    --create-namespace \
    --version "${FALCO_VERSION}" \
    --timeout 15m \
    --set driver.kind=modern_ebpf \
    --set driver.loader.enabled=false \
    --set falcosidekick.enabled=true \
    --set falcosidekick.config.loki.hostport="http://loki.monitoring:3100" \
    --set falcosidekick.config.slack.webhookurl="${SLACK_WEBHOOK_URL:-}" \
    --values falco/falco-values.yaml

# Falco DaemonSet peut prendre plusieurs minutes à charger le driver eBPF
# On attend de manière non-bloquante (sans --wait helm) pour éviter timeout
log "Attente du démarrage des pods Falco (jusqu'à 5 min)..."
sleep 30
for i in $(seq 1 10); do
    READY=$(kubectl get pods -n falco --field-selector=status.phase=Running \
        --no-headers 2>/dev/null | wc -l | tr -d ' ')
    TOTAL=$(kubectl get pods -n falco --no-headers 2>/dev/null | wc -l | tr -d ' ')
    log "  Pods Falco prêts : ${READY}/${TOTAL} (tentative ${i}/10)"
    if [ "${READY:-0}" -ge 1 ] 2>/dev/null; then
        break
    fi
    sleep 30
done
kubectl get pods -n falco || true

# Application des règles personnalisées
kubectl create configmap falco-custom-rules \
    --from-file=falco/custom-rules.yaml \
    --namespace falco \
    --dry-run=client -o yaml | kubectl apply -f -

log "Falco installé avec règles personnalisées."

# ---------------------------------------------------------------------------
# Étape 6 : Stack d'observabilité (Prometheus + Grafana + Loki)
# ---------------------------------------------------------------------------
log "Installation de la stack d'observabilité..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update
helm repo add grafana https://grafana.github.io/helm-charts --force-update
helm repo update

# Prometheus + Grafana
helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
    --namespace monitoring \
    --create-namespace \
    --version "60.0.0" \
    --timeout 15m \
    --values monitoring/prometheus-values.yaml

log "Attente des pods Prometheus/Grafana..."
sleep 30
kubectl wait --for=condition=ready pod \
    --selector='app.kubernetes.io/name=grafana' \
    --namespace monitoring \
    --timeout=300s || \
kubectl wait --for=condition=ready pod \
    --selector='app=grafana' \
    --namespace monitoring \
    --timeout=120s || true

# Loki
helm upgrade --install loki grafana/loki-stack \
    --namespace monitoring \
    --version "2.10.2" \
    --timeout 10m \
    --set grafana.enabled=false \
    --set promtail.enabled=true

log "Stack d'observabilité installée."

# ---------------------------------------------------------------------------
# Étape 7 : Déploiement de l'application cible
# ---------------------------------------------------------------------------
log "Construction de l'image Docker locale..."
LOCAL_IMAGE="devsecops-lab/target-api:local"
docker build -t "${LOCAL_IMAGE}" app/
log "Image construite : ${LOCAL_IMAGE}"

log "Import de l'image dans le cluster k3d..."
k3d image import "${LOCAL_IMAGE}" --cluster "${CLUSTER_NAME}"
log "Image importée."

# Passage temporaire de verify-image-signature en Audit
# (l'image locale n'a pas de signature Cosign — sera réactivée pour le scénario B)
log "Mode Audit pour verify-image-signature (déploiement initial)..."
kubectl patch clusterpolicy verify-image-signature \
    --type=merge \
    -p '{"spec":{"validationFailureAction":"Audit"}}' || true

log "Déploiement de l'application cible..."
# Remplacer IMAGE_PLACEHOLDER par l'image locale
sed "s|IMAGE_PLACEHOLDER|${LOCAL_IMAGE}|g" infra/k8s/deployment.yaml \
    | kubectl apply -f -

# Patcher imagePullPolicy à IfNotPresent (l'image est déjà dans k3d)
kubectl patch deployment target-api \
    --namespace app \
    --type=json \
    -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"IfNotPresent"}]'

kubectl apply -f infra/k8s/postgres.yaml

kubectl rollout status deployment/target-api \
    --namespace app \
    --timeout=180s
kubectl rollout status deployment/postgres \
    --namespace app \
    --timeout=120s || true
log "Application cible déployée."

# ---------------------------------------------------------------------------
# Résumé
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}========================================================${NC}"
echo -e "${GREEN}  Laboratoire DevSecOps opérationnel${NC}"
echo -e "${GREEN}========================================================${NC}"
echo ""
kubectl get pods --all-namespaces | grep -v "kube-system"
echo ""
log "Accès Grafana : kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring"
log "Accès Falcosidekick UI : kubectl port-forward svc/falco-falcosidekick-ui 2802:2802 -n falco"
log "Accès App : kubectl port-forward svc/target-api 8000:80 -n app"
