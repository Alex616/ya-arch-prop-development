#!/bin/bash

# Скрипт проверки безопасности namespace audit-zone
# Проверяет PodSecurity политики и применение безопасных манифестов

set -e

NAMESPACE="audit-zone"
SECURE_MANIFESTS_DIR="../secure-manifests"

echo "=== Проверка безопасности namespace $NAMESPACE ==="
echo ""

# Проверка существования namespace
echo "[1/5] Проверка существования namespace..."
if kubectl get namespace "$NAMESPACE" &>/dev/null; then
    echo "✓ Namespace $NAMESPACE существует"
else
    echo "✗ Namespace $NAMESPACE не найден"
    exit 1
fi

# Проверка PodSecurity labels
echo ""
echo "[2/5] Проверка PodSecurity политик..."
ENFORCE_LABEL=$(kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')
AUDIT_LABEL=$(kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/audit}')
WARN_LABEL=$(kubectl get namespace "$NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/warn}')

if [[ "$ENFORCE_LABEL" == "restricted" && "$AUDIT_LABEL" == "restricted" && "$WARN_LABEL" == "restricted" ]]; then
    echo "✓ PodSecurity политика: restricted (enforce/audit/warn)"
else
    echo "✗ PodSecurity политика настроена неверно"
    echo "  enforce: $ENFORCE_LABEL (ожидается: restricted)"
    echo "  audit: $AUDIT_LABEL (ожидается: restricted)"
    echo "  warn: $WARN_LABEL (ожидается: restricted)"
    exit 1
fi

# Проверка применения безопасных манифестов
echo ""
echo "[3/5] Проверка валидности безопасных манифестов..."

# Проверка существования директории
if [ ! -d "$SECURE_MANIFESTS_DIR" ]; then
    echo "✗ Директория $SECURE_MANIFESTS_DIR не найдена"
    exit 1
fi

# Проверка наличия файлов
MANIFEST_COUNT=$(find "$SECURE_MANIFESTS_DIR" -maxdepth 1 -name "*.yaml" -type f | wc -l)
if [ "$MANIFEST_COUNT" -eq 0 ]; then
    echo "✗ Не найдено *.yaml файлов в $SECURE_MANIFESTS_DIR"
    exit 1
fi

for manifest in "$SECURE_MANIFESTS_DIR"/*.yaml; do
    # Пропускаем если glob не раскрылся
    [ -f "$manifest" ] || continue

    filename=$(basename "$manifest")
    echo -n "  Проверка $filename... "
    if kubectl apply -f "$manifest" --dry-run=server &>/dev/null; then
        echo "✓"
    else
        echo "✗ Ошибка применения"
        kubectl apply -f "$manifest" --dry-run=server
        exit 1
    fi
done

# Проверка securityContext в безопасных манифестах
echo ""
echo "[4/5] Проверка securityContext в манифестах..."
for manifest in "$SECURE_MANIFESTS_DIR"/*.yaml; do
    [ -f "$manifest" ] || continue
    filename=$(basename "$manifest")
    echo "  Проверка $filename:"

    # Проверка runAsNonRoot на уровне Pod
    if grep -q "runAsNonRoot: true" "$manifest"; then
        echo "    ✓ runAsNonRoot: true"
    else
        echo "    ✗ Отсутствует runAsNonRoot: true"
        exit 1
    fi

    # Проверка allowPrivilegeEscalation
    if grep -q "allowPrivilegeEscalation: false" "$manifest"; then
        echo "    ✓ allowPrivilegeEscalation: false"
    else
        echo "    ✗ Отсутствует allowPrivilegeEscalation: false"
        exit 1
    fi

    # Проверка capabilities
    if grep -q "drop:" "$manifest" && grep -q -e "- ALL" "$manifest"; then
        echo "    ✓ capabilities drop ALL"
    else
        echo "    ✗ Отсутствует capabilities drop ALL"
        exit 1
    fi

    # Проверка seccompProfile
    if grep -q "seccompProfile:" "$manifest" && grep -q "type: RuntimeDefault" "$manifest"; then
        echo "    ✓ seccompProfile: RuntimeDefault"
    else
        echo "    ✗ Отсутствует seccompProfile RuntimeDefault"
        exit 1
    fi
done

# Проверка отсутствия hostPath
echo ""
echo "[5/5] Проверка отсутствия hostPath volumes..."
for manifest in "$SECURE_MANIFESTS_DIR"/*.yaml; do
    [ -f "$manifest" ] || continue
    filename=$(basename "$manifest")
    if grep -q "hostPath:" "$manifest"; then
        echo "✗ $filename содержит hostPath volume"
        exit 1
    fi
done
echo "✓ Все манифесты используют безопасные типы volumes"

echo ""
echo "=== Все проверки пройдены успешно ==="
echo ""
echo "Рекомендации:"
echo "- Примените манифесты: kubectl apply -f $SECURE_MANIFESTS_DIR/"
echo "- Запустите verify-admission.sh для проверки блокировки небезопасных подов"
