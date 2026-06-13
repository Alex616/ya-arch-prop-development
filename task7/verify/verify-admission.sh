#!/bin/bash

# Скрипт проверки Admission Control
# Проверяет блокировку небезопасных подов через PodSecurity и OPA Gatekeeper

set -e

NAMESPACE="audit-zone"
INSECURE_MANIFESTS_DIR="../insecure-manifests"

echo "=== Проверка Admission Control для namespace $NAMESPACE ==="
echo ""

# Проверка установки Gatekeeper
echo "[1/4] Проверка установки OPA Gatekeeper..."
if kubectl get deployment gatekeeper-controller-manager -n gatekeeper-system &>/dev/null; then
    echo "✓ Gatekeeper установлен"
    GATEKEEPER_INSTALLED=true
else
    echo "⚠ Gatekeeper не установлен (проверка только PodSecurity)"
    GATEKEEPER_INSTALLED=false
fi

# Проверка ConstraintTemplates (если Gatekeeper установлен)
if [ "$GATEKEEPER_INSTALLED" = true ]; then
    echo ""
    echo "[2/4] Проверка ConstraintTemplates..."
    TEMPLATES=("k8spspprivilegedcontainer" "k8spsphostfilesystem" "k8spsprunasnonroot")
    for template in "${TEMPLATES[@]}"; do
        if kubectl get constrainttemplate "$template" &>/dev/null; then
            echo "  ✓ $template"
        else
            echo "  ✗ $template не найден"
            echo "  Примените: kubectl apply -f ../gatekeeper/constraint-templates/"
            exit 1
        fi
    done

    # Проверка Constraints
    echo ""
    echo "[3/4] Проверка Constraints для namespace $NAMESPACE..."
    CONSTRAINTS=(
        "k8spspprivilegedcontainer/deny-privileged-containers"
        "k8spsphostfilesystem/deny-hostpath-volumes"
        "k8spsprunasnonroot/require-run-as-nonroot"
    )
    for constraint in "${CONSTRAINTS[@]}"; do
        kind=$(echo "$constraint" | cut -d'/' -f1)
        name=$(echo "$constraint" | cut -d'/' -f2)
        if kubectl get "$kind" "$name" &>/dev/null; then
            echo "  ✓ $name"
        else
            echo "  ✗ $name не найден"
            echo "  Примените: kubectl apply -f ../gatekeeper/constraints/"
            exit 1
        fi
    done
else
    echo ""
    echo "[2/4] Пропуск проверки Gatekeeper (не установлен)"
    echo "[3/4] Пропуск проверки Gatekeeper (не установлен)"
fi

# Проверка блокировки небезопасных подов
echo ""
echo "[4/4] Проверка блокировки небезопасных манифестов..."

test_manifest() {
    local manifest=$1
    local filename
    filename=$(basename "$manifest")

    echo ""
    echo "  Тестирование: $filename"

    # Попытка применения с dry-run
    if kubectl apply -f "$manifest" --dry-run=server 2>&1 | tee /tmp/admission-test.log | grep -q "forbidden\|denied\|violates"; then
        echo "    ✓ Заблокирован (как и ожидалось)"
        echo "    Причина:"
        grep -E "forbidden|denied|violates|Error" /tmp/admission-test.log | sed 's/^/      /'
        return 0
    else
        echo "    ✗ НЕ заблокирован (ожидалась блокировка)"
        echo "    Лог:"
        cat /tmp/admission-test.log | sed 's/^/      /'
        return 1
    fi
}

FAILED=0

# Тест 1: Привилегированный контейнер
if ! test_manifest "$INSECURE_MANIFESTS_DIR/01-privileged-pod.yaml" "privileged"; then
    FAILED=$((FAILED + 1))
fi

# Тест 2: hostPath volume
if ! test_manifest "$INSECURE_MANIFESTS_DIR/02-hostpath-pod.yaml" "hostPath"; then
    FAILED=$((FAILED + 1))
fi

# Тест 3: Root пользователь
if ! test_manifest "$INSECURE_MANIFESTS_DIR/03-root-user-pod.yaml" "runAsNonRoot"; then
    FAILED=$((FAILED + 1))
fi

# Очистка
rm -f /tmp/admission-test.log

# Итоги
echo ""
if [ $FAILED -eq 0 ]; then
    echo "=== Все проверки Admission Control пройдены успешно ==="
    echo ""
    echo "✓ Небезопасные поды корректно блокируются"
    if [ "$GATEKEEPER_INSTALLED" = true ]; then
        echo "✓ PodSecurity и Gatekeeper работают совместно"
    else
        echo "✓ PodSecurity защищает namespace"
        echo ""
        echo "Для дополнительной защиты рекомендуется установить Gatekeeper:"
        echo "  kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml"
        echo "  kubectl apply -f ../gatekeeper/constraint-templates/"
        echo "  kubectl apply -f ../gatekeeper/constraints/"
    fi
else
    echo "=== Обнаружены проблемы: $FAILED тест(ов) провалено ==="
    echo ""
    echo "Возможные причины:"
    echo "- Namespace не имеет PodSecurity labels"
    echo "- Gatekeeper не установлен или не настроен"
    echo "- ConstraintTemplates/Constraints не применены"
    exit 1
fi
