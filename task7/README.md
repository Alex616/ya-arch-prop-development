# Task 7: Настройка безопасности Kubernetes с PodSecurity и OPA Gatekeeper

Демонстрация настройки политик безопасности для Kubernetes namespace с использованием встроенного PodSecurity Admission и OPA Gatekeeper.

### 1. Установка

Запустите скрипт установки из директории `task7/`:

```bash
./install-security.sh
```

Скрипт выполнит:

- Создание namespace `audit-zone` с PodSecurity restricted
- Установку OPA Gatekeeper (опционально, с подтверждением)
- Применение ConstraintTemplates и Constraints
- Применение примеров безопасных подов (опционально)

### 2. Проверка безопасности

После установки запустите проверки:

```bash
cd verify

# Проверка настроек безопасности
./validate-security.sh

# Проверка блокировки небезопасных подов
./verify-admission.sh
```
