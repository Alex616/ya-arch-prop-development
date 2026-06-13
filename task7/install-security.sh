#!/bin/bash

# Скрипт установки и настройки безопасности для namespace audit-zone
# Применяет PodSecurity политики и настраивает OPA Gatekeeper

set -e

NAMESPACE="audit-zone"
NAMESPACE_MANIFEST="01-create-namespace.yml"
GATEKEEPER_TEMPLATES_DIR="gatekeeper/constraint-templates"
GATEKEEPER_CONSTRAINTS_DIR="gatekeeper/constraints"
SECURE_MANIFESTS_DIR="secure-manifests"

echo "=== Установка и настройка безопасности ==="
echo ""

# Проверка наличия kubectl
if ! command -v kubectl &>/dev/null; then
  echo "✗ kubectl не найден. Установите kubectl для продолжения."
  exit 1
fi

# Проверка подключения к кластеру
echo "[1/7] Проверка подключения к кластеру..."
if ! kubectl cluster-info &>/dev/null; then
  echo "✗ Не удается подключиться к кластеру Kubernetes"
  echo "  Проверьте настройки kubeconfig"
  exit 1
fi
CLUSTER_NAME=$(kubectl config current-context)
echo "✓ Подключен к кластеру: $CLUSTER_NAME"

# Создание namespace с PodSecurity
echo ""
echo "[2/7] Создание namespace $NAMESPACE с PodSecurity restricted..."
if kubectl get namespace "$NAMESPACE" &>/dev/null; then
  echo "  Namespace уже существует, обновление labels..."
  kubectl apply -f "$NAMESPACE_MANIFEST"
else
  kubectl apply -f "$NAMESPACE_MANIFEST"
  echo "✓ Namespace $NAMESPACE создан"
fi

# Проверка PodSecurity labels
ENFORCE_LABEL=$(kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')
if [[ "$ENFORCE_LABEL" == "restricted" ]]; then
  echo "✓ PodSecurity политика: restricted"
else
  echo "✗ PodSecurity политика не применена корректно"
  exit 1
fi

# Проверка/установка Gatekeeper
echo ""
echo "[3/7] Проверка установки OPA Gatekeeper..."
if kubectl get namespace gatekeeper-system &>/dev/null; then
  echo "✓ Gatekeeper уже установлен"
  GATEKEEPER_INSTALLED=true
else
  echo "  Gatekeeper не установлен"
  read -p "  Установить Gatekeeper? (y/n): " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "  Установка Gatekeeper..."
    kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

    # Ожидание готовности Gatekeeper
    echo "  Ожидание готовности Gatekeeper (до 2 минут)..."
    kubectl wait --for=condition=available --timeout=120s \
      deployment/gatekeeper-controller-manager -n gatekeeper-system
    kubectl wait --for=condition=available --timeout=120s \
      deployment/gatekeeper-audit -n gatekeeper-system

    echo "✓ Gatekeeper установлен"
    GATEKEEPER_INSTALLED=true
  else
    echo "  Пропуск установки Gatekeeper"
    GATEKEEPER_INSTALLED=false
  fi
fi

# Применение ConstraintTemplates
if [ "$GATEKEEPER_INSTALLED" = true ]; then
  echo ""
  echo "[4/7] Применение ConstraintTemplates..."
  for template in "$GATEKEEPER_TEMPLATES_DIR"/*.yaml; do
    filename=$(basename "$template")
    echo -n "  Применение $filename... "
    kubectl apply -f "$template"
    echo "✓"
  done

  # Применение Constraints
  echo ""
  echo "[5/7] Применение Constraints для namespace $NAMESPACE..."
  for constraint in "$GATEKEEPER_CONSTRAINTS_DIR"/*.yaml; do
    filename=$(basename "$constraint")
    echo -n "  Применение $filename... "
    kubectl apply -f "$constraint"
    echo "✓"
  done
else
  echo ""
  echo "[4/7] Пропуск ConstraintTemplates (Gatekeeper не установлен)"
  echo "[5/7] Пропуск Constraints (Gatekeeper не установлен)"
fi

# Применение безопасных манифестов (опционально)
echo ""
echo "[6/7] Применение безопасных манифестов..."
read -p "  Применить примеры безопасных подов? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  for manifest in "$SECURE_MANIFESTS_DIR"/*.yaml; do
    filename=$(basename "$manifest")
    echo -n "  Применение $filename... "
    kubectl apply -f "$manifest"
    echo "✓"
  done
  echo "✓ Безопасные поды созданы"
else
  echo "  Пропуск применения примеров"
fi

# Итоговая проверка
echo ""
echo "[7/7] Проверка конфигурации..."

echo ""
echo "Namespace $NAMESPACE:"
kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.labels}' | grep pod-security || echo "  Нет PodSecurity labels"

if [ "$GATEKEEPER_INSTALLED" = true ]; then
  echo ""
  echo "ConstraintTemplates:"
  kubectl get constrainttemplates 2>/dev/null | grep -E "k8spsp|NAME" || echo "  Нет ConstraintTemplates"

  echo ""
  echo "Constraints для $NAMESPACE:"
  kubectl get constraints -A 2>/dev/null | grep -E "$NAMESPACE|NAME" || echo "  Нет Constraints"
fi

echo ""
echo "Поды в namespace $NAMESPACE:"
kubectl get pods -n "$NAMESPACE" 2>/dev/null || echo "  Нет подов"
