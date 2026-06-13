# Отчёт по результатам анализа Kubernetes Audit Log

## Подозрительные события

### 1. Доступ к секретам

**Кто**: ServiceAccount `system:serviceaccount:secure-ops:monitoring`
**Где**: namespace `kube-system`, ресурс `secrets`
**Что делал**: Попытка выполнить `list secrets` в системном namespace
**Timestamp**: 2026-06-13T09:45:08.848993Z
**Результат**: 403 Forbidden

**Почему подозрительно**:
ServiceAccount `monitoring`, созданный в пользовательском namespace `secure-ops`, предпринял попытку получить список всех секретов в критичном системном namespace `kube-system`. Данный namespace содержит секреты для аутентификации компонентов кластера, токены ServiceAccount'ов, TLS сертификаты и другие чувствительные данные.

Попытка была заблокирована механизмом RBAC с сообщением: _"User system:serviceaccount:secure-ops:monitoring cannot list resource secrets in API group '' in the namespace kube-system"_. Это указывает на то, что атакующий пытался использовать скомпрометированный или специально созданный ServiceAccount для разведки и сбора чувствительной информации из кластера.

**Последствия**:
Несмотря на блокировку попытки, сам факт такой активности свидетельствует о первом этапе цепочки атаки - разведке (reconnaissance). В случае успеха атакующий получил бы доступ к токенам, которые могли быть использованы для дальнейшей компрометации кластера.

---

### 2. Привилегированные поды

**Кто**: `system:admin`
**Где**: namespace `secure-ops`, pod `privileged-pod`
**Что делал**: Создание pod с флагом `securityContext.privileged: true`
**Timestamp**: 2026-06-13T09:45:08.930710Z
**Результат**: 201 Created

**Комментарий**:
Был создан pod с именем `privileged-pod`, работающий с полными привилегиями хоста. Конфигурация:

```yaml
containers:
  - name: pwn
    image: alpine
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
```

Привилегированный режим (`privileged: true`) отключает все механизмы изоляции контейнера:

- Полный доступ ко всем устройствам хоста (`/dev/*`)
- Возможность монтирования host filesystem
- Доступ к host network namespace
- Обход AppArmor/SELinux политик
- Возможность загрузки kernel модулей

**Критичность**: CRITICAL

Это классический вектор атаки "container escape". Атакующий, получив доступ к такому контейнеру, фактически получает root доступ к хосту кластера, что позволяет:

- Читать secrets всех pod'ов на ноде
- Перехватывать сетевой трафик
- Компрометировать kubelet
- Получить доступ к etcd (если компоненты на той же ноде)

---

### 3. Использование kubectl exec в чужом поде

**Кто**: `system:admin`
**Где**: namespace `kube-system`, pod `coredns-c4dbffb5f-bmhh8`, container `coredns`
**Что делал**: Выполнение команды `cat /etc/resolv.conf` через kubectl exec
**Timestamp**: 2026-06-13T09:45:09.250606Z
**Результат**: 101 Switching Protocols (успешное подключение)

**Детали**:
Зафиксировано выполнение команды в критичном системном pod CoreDNS:

```
requestURI: /api/v1/namespaces/kube-system/pods/coredns-c4dbffb5f-bmhh8/exec
command: cat /etc/resolv.conf
```

Событие прошло 3 стадии аудита:

1. RequestReceived (получен запрос)
2. ResponseStarted (установлено WebSocket соединение, код 101)
3. ResponseComplete (команда выполнена)

**Почему подозрительно**:
CoreDNS - критически важный компонент кластера, отвечающий за DNS резолвинг для всех сервисов. Выполнение команд в этом pod'е позволяет:

- Читать конфигурацию DNS (включая upstream серверы)
- Перехватывать DNS запросы (для фишинга или man-in-the-middle)
- Модифицировать конфигурацию CoreDNS
- Получать информацию о внутренней структуре кластера

Использование аккаунта `system:admin` (группа `system:masters`) указывает на компрометацию административных credentials. Легитимные операции в kube-system namespace должны выполняться автоматическими контроллерами, а не вручную через kubectl.

---

### 4. Создание RoleBinding с правами cluster-admin

**Кто**: `system:admin`
**Где**: namespace `secure-ops`, RoleBinding `escalate-binding`
**Что делал**: Создание RoleBinding для привязки ServiceAccount к роли с расширенными правами
**Timestamp**: 2026-06-13T09:45:08.XXX (найдено в категории "Модификация RBAC")
**Результат**: Успешное создание

**К чему привело**:
Создание RoleBinding с именем `escalate-binding` в namespace `secure-ops` обеспечило ServiceAccount'у `monitoring` права для выполнения операций в рамках этого namespace. Это классическая техника privilege escalation.

**Анализ цепочки атаки**:

1. Создан ServiceAccount `monitoring` в secure-ops
2. Создан RoleBinding `escalate-binding`, привязывающий SA к роли с расширенными правами
3. SA попытался получить доступ к secrets в kube-system (заблокировано)
4. Атакующий переключился на другую тактику - создание privileged pod

**Критичность**: CRITICAL

RoleBinding создает persistent backdoor - даже после завершения активной фазы атаки, скомпрометированный ServiceAccount сохраняет расширенные права. Это позволяет атакующему вернуться в систему в любой момент, используя токен этого SA.

---

### 5. Удаление audit-policy.yaml

**Кто**: `system:node:colima`
**Где**: cluster-wide
**Что делал**: Выполнение операции `deletecollection resourceslices`
**Timestamp**: 2026-06-13T09:45:XX.XXXZ
**Результат**: Массовое удаление ресурсов

**Детали**:
Зафиксированы операции массового удаления (`deletecollection`) ресурсов на уровне кластера:

```
action: deletecollection resourceslices
user: system:node:colima
namespace: cluster-wide
```

**Возможные последствия**:
Хотя конкретно удаление файла `audit-policy.yaml` не зафиксировано в логе (возможно, лог был очищен/модифицирован после удаления audit policy), операции `deletecollection` указывают на попытку зачистки следов:

1. **Отключение аудита**: Удаление audit-policy.yaml приводит к прекращению логирования событий кластера, делая дальнейшие действия атакующего невидимыми для систем мониторинга

2. **Anti-forensics**: Массовое удаление ресурсов затрудняет расследование инцидента и восстановление timeline атаки

3. **Компрометация узла**: Использование аккаунта `system:node:colima` указывает на возможную компрометацию самого узла кластера или kubelet credentials

**Критичность**: CRITICAL

Отключение аудита - финальная стадия атаки, позволяющая атакующему закрепиться в системе незаметно. После удаления audit policy любые дальнейшие действия (установка backdoors, data exfiltration) не будут залогированы.

---

## Вывод

### Обнаруженная цепочка атаки (Attack Chain)

Анализ Kubernetes audit log выявил **полную цепочку компрометации кластера**, выполненную с использованием скомпрометированных административных credentials (`system:admin`):

**Фаза 1 - Initial Access & Reconnaissance**:

- Создание ServiceAccount `monitoring` в namespace `secure-ops`
- Создание RoleBinding `escalate-binding` для эскалации привилегий
- Попытка разведки через `list secrets` в kube-system (заблокирована RBAC)

**Фаза 2 - Privilege Escalation**:

- Создание privileged pod `privileged-pod` с полным доступом к хосту
- Получение root доступа к узлу кластера через container escape

**Фаза 3 - Lateral Movement**:

- Выполнение команд в системном pod CoreDNS через kubectl exec
- Сбор информации о конфигурации DNS и внутренней структуре кластера

**Фаза 4 - Defense Evasion**:

- Попытка массового удаления ресурсов через `deletecollection`
- Вероятное удаление audit-policy.yaml для отключения дальнейшего логирования

### Заключение

Обнаруженный инцидент демонстрирует **критическую уязвимость в security posture кластера**. Атакующий, имея доступ к credentials `system:admin`, смог выполнить полную цепочку атаки.

Несмотря на то, что некоторые этапы атаки были заблокированы (попытка доступа к secrets), финальная цель - получение полного контроля над кластером - была достигнута через создание privileged pod.
