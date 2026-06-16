# Mini-lab DevSecOps — Mémoire professionnel

Environnement de démonstration technique pour la Partie V du mémoire portant sur la sécurisation des pipelines CI/CD et des environnements cloud-native. Ce dépôt implémente le protocole expérimental défini dans le document annexe _Protocole expérimental du mini-lab_.

---

## Architecture

```
mini-lab/
├── app/                        # Application cible (FastAPI + PostgreSQL)
│   ├── main.py
│   ├── requirements.txt
│   └── Dockerfile
├── .github/workflows/
│   ├── pipeline.yml            # Pipeline sécurisé complet
│   └── baseline.yml            # Pipeline sans contrôles (mesure de référence)
├── infra/
│   ├── k3d-config.yaml         # Configuration cluster k3d
│   ├── setup-cluster.sh        # Script d'installation complet
│   └── k8s/                    # Manifests Kubernetes
├── policies/
│   ├── kyverno/                # 5 politiques Kyverno
│   └── opa-gatekeeper/         # Comparatif OPA Gatekeeper
├── falco/
│   ├── custom-rules.yaml       # Règles personnalisées
│   └── falco-values.yaml       # Configuration Helm
├── monitoring/
│   └── prometheus-values.yaml  # Stack Prometheus + Grafana + Loki
├── scenarios/
│   ├── A-vulnerable-image/     # CVE-2021-44228 (Log4Shell)
│   ├── B-unsigned-image/       # Supply chain (image non signée)
│   ├── C-shell-exec/           # T1609 — kubectl exec
│   ├── D-container-escape/     # T1611 — évasion vers l'hôte
│   └── E-privileged-pod/       # T1611 — configuration insecure
└── scripts/
    ├── run-all-scenarios.sh    # Exécution complète
    ├── collect-kpi.sh          # Agrégation des KPI
    ├── measure-false-positives.sh
    ├── generate-nominal-traffic.sh
    └── lib/kpi-utils.sh
```

---

## Prérequis

| Outil       | Version minimale | Installation                                    |
|-------------|------------------|-------------------------------------------------|
| Docker      | 24.x             | https://docs.docker.com/get-docker/             |
| kubectl     | 1.29             | https://kubernetes.io/docs/tasks/tools/         |
| k3d         | 5.6              | `brew install k3d` ou https://k3d.io            |
| Helm        | 3.14             | `brew install helm`                             |
| Cosign      | 2.x              | `brew install cosign`                           |
| Trivy       | 0.51             | `brew install trivy`                            |
| jq          | 1.7              | `brew install jq`                               |
| bc          | —                | préinstallé sur macOS/Linux                     |

Ressources matérielles recommandées : 8 Go RAM, 4 vCPU, 20 Go d'espace disque libre.

---

## Phase 1 — Préparation de l'environnement

### 1.1 Clonage et configuration

```bash
git clone https://github.com/ArifStephane/devsecops-mini-lab.git
cd devsecops-mini-lab

# Remplacer ArifStephane par votre identifiant GitHub dans les fichiers concernés
sed -i 's/ArifStephane/votre-username/g' \
    policies/kyverno/01-verify-image-signature.yaml \
    .github/workflows/pipeline.yml
```

### 1.2 Installation du cluster et des composants

```bash
bash infra/setup-cluster.sh
```

Ce script installe séquentiellement :
1. Cluster k3d (1 control-plane + 2 workers)
2. Kyverno v3.2 + politiques
3. Falco v4.6 + règles personnalisées
4. Prometheus + Grafana + Loki
5. Application cible

Durée estimée : 10-15 minutes.

### 1.3 Vérification de l'installation

```bash
# État global du cluster
kubectl get pods --all-namespaces

# Application cible accessible
kubectl port-forward svc/target-api 8000:80 -n app &
curl http://localhost:8000/health

# Interface Grafana
kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring &
# Ouvrir http://localhost:3000 (admin / lab-admin-2024)
```

---

## Phase 2 — Baseline (sans contrôles)

```bash
# Lancer le workflow baseline depuis GitHub Actions (manuel)
# Ou simuler localement :
docker build -t target-api:baseline ./app
docker push ghcr.io/ArifStephane/devsecops-mini-lab/target-api:baseline

# Mesurer la durée du pipeline baseline
# → récupérer l'artefact "baseline-metrics-*" depuis l'onglet Actions
```

---

## Phase 3 — Configuration shift-left

Activer uniquement les contrôles CI/CD (désactiver Kyverno et Falco) :

```bash
# Suspendre Kyverno
kubectl scale deployment kyverno-admission-controller -n kyverno --replicas=0

# Exécuter les scénarios A et B uniquement
bash scenarios/A-vulnerable-image/run-scenario-a.sh
bash scenarios/B-unsigned-image/run-scenario-b.sh

# Collecter les KPI shift-left
bash scripts/collect-kpi.sh shift-left
```

---

## Phase 4 — Configuration shift-everywhere (principale)

```bash
# Réactiver Kyverno
kubectl scale deployment kyverno-admission-controller -n kyverno --replicas=1

# Exécution complète des 5 scénarios
bash scripts/run-all-scenarios.sh shift-everywhere
```

### Accès aux résultats en temps réel

```bash
# Alertes Falco en direct
kubectl logs -f -n falco -l app.kubernetes.io/name=falco | grep -v "^$"

# Interface Falcosidekick
kubectl port-forward svc/falco-falcosidekick-ui 2802:2802 -n falco &
# Ouvrir http://localhost:2802

# Métriques pipeline (GitHub Actions → onglet Actions → artefacts)
```

---

## Phase 5 — Analyse et rapport KPI

```bash
# Rapport KPI consolidé
bash scripts/collect-kpi.sh shift-everywhere

# Les résultats JSON sont dans scripts/results/
ls scripts/results/
```

### Structure d'un rapport KPI

```json
{
  "kpi": {
    "tpr_detection_rate":  { "value": 80.0, "threshold_h1": 80.0 },
    "mttd_mean":           { "value_seconds": 2.3, "sla_seconds": 5 },
    "pipeline_overhead":   { "value": 12.5, "threshold_h1": 15.0 },
    "mitre_coverage":      { "value": 77.8, "techniques_covered": [...] }
  }
}
```

---

## Critères de validation des hypothèses

| Hypothèse | Critère de validation | KPI concerné |
|-----------|----------------------|--------------|
| H1 | TPR ≥ 80% ET surcoût pipeline < 15% | `tpr_detection_rate`, `pipeline_overhead` |
| H2 | FPR ruleset défaut > 20%, réduit < 5% après tuning | `fpr_percent` |
| H3 | CFR réduit ≥ 30% ET dégradation Lead Time < 10% | `change_failure_rate`, `lead_time` |

---

## Configurations testées

| Configuration      | Hadolint | Trivy | Cosign | Kyverno | Falco |
|--------------------|:--------:|:-----:|:------:|:-------:|:-----:|
| Baseline           | ✗        | ✗     | ✗      | ✗       | ✗     |
| Shift-left         | ✓        | ✓     | ✓      | ✗       | ✗     |
| Shift-everywhere   | ✓        | ✓     | ✓      | ✓       | ✓     |
| Runtime-only       | ✗        | ✗     | ✗      | ✗       | ✓     |

---

## Limites méthodologiques

Conformément au protocole expérimental (section 7), les résultats de ce laboratoire sont obtenus dans un environnement contrôlé et ne sont pas directement transposables à un environnement de production. Les principales limites sont : l'absence de charge applicative complexe, la durée d'observation réduite pour la mesure du FPR (session de laboratoire vs. 24h recommandées), l'exclusion des solutions CNAPP commerciales, et la limitation aux outils open source.

---

## Références

- Falco : https://falco.org/docs/
- Kyverno : https://kyverno.io/policies/
- Trivy : https://aquasecurity.github.io/trivy/
- Cosign / Sigstore : https://docs.sigstore.dev/
- MITRE ATT&CK for Containers : https://attack.mitre.org/matrices/enterprise/containers/
- CIS Kubernetes Benchmark : https://www.cisecurity.org/benchmark/kubernetes
