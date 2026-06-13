#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Анализатор Kubernetes audit.log для выявления небезопасных действий
"""

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List

# Константы для правил детектирования
SENSITIVE_RESOURCES = [
    'secrets', 'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings',
    'serviceaccounts'
]
DANGEROUS_VERBS = ['delete', 'deletecollection']
CRITICAL_NAMESPACES = ['kube-system', 'secure-ops', 'default']
DANGEROUS_RESOURCES_TO_DELETE = [
    'namespaces', 'deployments', 'persistentvolumes', 'persistentvolumeclaims'
]
PRIVILEGE_ESCALATION_RESOURCES = [
    'validatingwebhookconfigurations', 'mutatingwebhookconfigurations'
]
KNOWN_INTERNAL_IPS = ['127.0.0.1', '::1']
STANDARD_USER_AGENTS = [
    'k3s', 'kubectl', 'kubernetes', 'kube-controller-manager',
    'kube-scheduler', 'kube-apiserver'
]

# Ключевые слова для поиска credentials в configmaps
CREDENTIAL_KEYWORDS = [
    'password', 'token', 'secret', 'key', 'credential', 'auth'
]

# Приоритет severity для сортировки
SEVERITY_PRIORITY = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}


def load_audit_events(file_path: str) -> List[Dict[str, Any]]:
    """Загрузка событий из audit.log"""
    events = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                events.append(event)
            except json.JSONDecodeError as e:
                print(f"Ошибка парсинга строки {line_num}: {e}")
    return events


def extract_event_info(event: Dict[str, Any]) -> Dict[str, Any]:
    """Извлечение основной информации из события"""
    user_info = event.get('user', {})
    object_ref = event.get('objectRef', {})
    response_status = event.get('responseStatus', {})

    return {
        'timestamp':
        event.get('requestReceivedTimestamp', ''),
        'user':
        user_info.get('username', 'unknown'),
        'user_groups':
        user_info.get('groups', []),
        'verb':
        event.get('verb', ''),
        'resource':
        object_ref.get('resource', ''),
        'resource_name':
        object_ref.get('name', ''),
        'namespace':
        object_ref.get('namespace', ''),
        'apiVersion':
        object_ref.get('apiVersion', ''),
        'subresource':
        object_ref.get('subresource', ''),
        'response_code':
        response_status.get('code', 0),
        'response_message':
        response_status.get('message', ''),
        'source_ips':
        event.get('sourceIPs', []),
        'user_agent':
        event.get('userAgent', ''),
        'authorization':
        event.get('annotations', {}).get('authorization.k8s.io/decision', ''),
        'request_uri':
        event.get('requestURI', ''),
    }


def create_finding(severity: str, category: str, info: Dict[str, Any],
                   description: str, event: Dict[str, Any]) -> Dict[str, Any]:
    """Создание записи о находке"""
    resource_full = f"{info['resource']}"
    if info['resource_name']:
        resource_full += f"/{info['resource_name']}"
    if info['subresource']:
        resource_full += f":{info['subresource']}"

    action = f"{info['verb']} {info['resource']}"

    return {
        'severity': severity,
        'category': category,
        'timestamp': info['timestamp'],
        'user': info['user'],
        'action': action,
        'resource': resource_full,
        'namespace': info['namespace'] or 'cluster-wide',
        'description': description,
        'source_ips': info['source_ips'],
        'user_agent': info['user_agent'],
        'response_code': info['response_code'],
        'original_event': event
    }


def analyze_authorization_issues(
        info: Dict[str, Any], event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Анализ проблем авторизации"""
    findings = []

    # HTTP коды 401, 403
    if info['response_code'] in [401, 403]:
        findings.append(
            create_finding(
                'HIGH', 'authorization', info,
                f"Неавторизованный доступ (код {info['response_code']}): {info['response_message']}",
                event))

    # Authorization decision deny
    if info['authorization'] == 'deny':
        findings.append(
            create_finding('HIGH', 'authorization', info,
                           "Отказ в авторизации операции", event))

    # Rate limiting
    if info['response_code'] == 429:
        findings.append(
            create_finding(
                'HIGH', 'authorization', info,
                "Превышение лимита запросов (возможная атака перебором)",
                event))

    return findings


def analyze_sensitive_resources(info: Dict[str, Any],
                                event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Анализ операций с чувствительными ресурсами"""
    findings = []
    resource = info['resource']
    verb = info['verb']

    # Операции с secrets
    if resource == 'secrets':
        if verb in ['create', 'update', 'patch', 'delete']:
            findings.append(
                create_finding('CRITICAL', 'sensitive_resources', info,
                               f"Модификация секретов ({verb})", event))
        elif verb in ['get', 'list', 'watch']:
            findings.append(
                create_finding('HIGH', 'sensitive_resources', info,
                               f"Чтение секретов ({verb})", event))

    # Операции с configmaps (проверка на credentials)
    if resource == 'configmaps':
        # Проверяем имя configmap на наличие credential keywords
        resource_name_lower = info['resource_name'].lower()
        if any(keyword in resource_name_lower
               for keyword in CREDENTIAL_KEYWORDS):
            severity = 'CRITICAL' if verb in [
                'create', 'update', 'patch', 'delete'
            ] else 'HIGH'
            findings.append(
                create_finding(
                    severity, 'sensitive_resources', info,
                    f"Операция с configmap, содержащим credentials ({verb})",
                    event))

    # Модификация RBAC
    if resource in [
            'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings'
    ]:
        if verb in ['create', 'update', 'patch', 'delete']:
            findings.append(
                create_finding('CRITICAL', 'sensitive_resources', info,
                               f"Модификация RBAC ({verb} {resource})", event))

    # Операции с serviceaccounts
    if resource == 'serviceaccounts':
        if verb in ['create', 'update', 'patch', 'delete']:
            findings.append(
                create_finding('HIGH', 'sensitive_resources', info,
                               f"Модификация service account ({verb})", event))

    return findings


def analyze_dangerous_operations(
        info: Dict[str, Any], event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Анализ опасных операций"""
    findings = []
    resource = info['resource']
    verb = info['verb']
    namespace = info['namespace']
    subresource = info['subresource']

    # Delete критических ресурсов
    if verb == 'delete' and resource in DANGEROUS_RESOURCES_TO_DELETE:
        findings.append(
            create_finding('CRITICAL', 'dangerous_operations', info,
                           f"Удаление критического ресурса ({resource})",
                           event))

    # Массовое удаление
    if verb == 'deletecollection':
        findings.append(
            create_finding('CRITICAL', 'dangerous_operations', info,
                           f"Массовое удаление ресурсов ({resource})", event))

    # Создание привилегированных pods
    if resource == 'pods' and verb == 'create':
        # Проверяем request body на privileged: true
        request_object = event.get('requestObject', {})
        spec = request_object.get('spec', {})
        containers = spec.get('containers', [])

        for container in containers:
            security_context = container.get('securityContext', {})
            if security_context.get('privileged', False):
                findings.append(
                    create_finding('CRITICAL', 'dangerous_operations', info,
                                   "Создание привилегированного pod", event))
                break

    # Exec в контейнеры kube-system
    if subresource == 'exec' and namespace == 'kube-system':
        findings.append(
            create_finding(
                'CRITICAL', 'dangerous_operations', info,
                "Выполнение команд в контейнере kube-system namespace", event))

    return findings


def analyze_anomalies(info: Dict[str, Any],
                      event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Анализ аномалий и подозрительных паттернов"""
    findings = []

    # Доступ с необычных IP
    source_ips = info['source_ips']
    unusual_ips = [
        ip for ip in source_ips if ip not in KNOWN_INTERNAL_IPS
        and not ip.startswith('10.') and not ip.startswith('192.168.')
    ]
    if unusual_ips:
        findings.append(
            create_finding(
                'MEDIUM', 'anomalies', info,
                f"Доступ с необычного IP адреса: {', '.join(unusual_ips)}",
                event))

    # Подозрительный User-Agent
    user_agent = info['user_agent']
    if user_agent and not any(standard in user_agent.lower()
                              for standard in STANDARD_USER_AGENTS):
        findings.append(
            create_finding('MEDIUM', 'anomalies', info,
                           f"Нестандартный User-Agent: {user_agent}", event))

    # Операции в критических namespaces от непривилегированных пользователей
    namespace = info['namespace']
    user = info['user']
    user_groups = info['user_groups']

    if namespace in CRITICAL_NAMESPACES:
        is_privileged = (user.startswith('system:')
                         or 'system:masters' in user_groups
                         or 'system:authenticated' in user_groups)
        if not is_privileged and info['verb'] not in ['get', 'list', 'watch']:
            findings.append(
                create_finding(
                    'MEDIUM', 'anomalies', info,
                    f"Операция в критическом namespace ({namespace}) от непривилегированного пользователя",
                    event))

    # Множественные ошибки 500
    if info['response_code'] >= 500:
        findings.append(
            create_finding(
                'MEDIUM', 'anomalies', info,
                f"Внутренняя ошибка сервера (код {info['response_code']}): {info['response_message']}",
                event))

    return findings


def analyze_privilege_escalation(
        info: Dict[str, Any], event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Анализ эскалации привилегий"""
    findings = []
    resource = info['resource']
    verb = info['verb']

    # Binding к cluster-admin
    if resource in ['rolebindings', 'clusterrolebindings'
                    ] and verb in ['create', 'update', 'patch']:
        request_object = event.get('requestObject', {})
        role_ref = request_object.get('roleRef', {})
        if role_ref.get('name') == 'cluster-admin':
            findings.append(
                create_finding(
                    'CRITICAL', 'privilege_escalation', info,
                    "Привязка к роли cluster-admin (полный доступ к кластеру)",
                    event))

    # Модификация admission controllers
    if resource in PRIVILEGE_ESCALATION_RESOURCES and verb in [
            'create', 'update', 'patch', 'delete'
    ]:
        findings.append(
            create_finding('CRITICAL', 'privilege_escalation', info,
                           f"Модификация admission controller ({resource})",
                           event))

    # Создание serviceaccount с повышенными правами (проверяем последующий binding)
    # Это требует контекстного анализа, поэтому помечаем только создание SA в критических namespace
    if resource == 'serviceaccounts' and verb == 'create' and info[
            'namespace'] in CRITICAL_NAMESPACES:
        findings.append(
            create_finding(
                'HIGH', 'privilege_escalation', info,
                f"Создание service account в критическом namespace ({info['namespace']})",
                event))

    return findings


def analyze_event(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Анализ одного события по всем правилам"""
    info = extract_event_info(event)
    findings = []

    # Применяем все правила детектирования
    findings.extend(analyze_authorization_issues(info, event))
    findings.extend(analyze_sensitive_resources(info, event))
    findings.extend(analyze_dangerous_operations(info, event))
    findings.extend(analyze_anomalies(info, event))
    findings.extend(analyze_privilege_escalation(info, event))

    return findings


def generate_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Генерация сводной статистики"""
    by_severity = defaultdict(int)
    by_category = defaultdict(int)
    by_user = defaultdict(int)
    by_namespace = defaultdict(int)

    for finding in findings:
        by_severity[finding['severity']] += 1
        by_category[finding['category']] += 1
        by_user[finding['user']] += 1
        by_namespace[finding['namespace']] += 1

    return {
        'by_severity':
        dict(by_severity),
        'by_category':
        dict(by_category),
        'by_user':
        dict(by_user),
        'by_namespace':
        dict(by_namespace),
        'top_users':
        sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:10],
        'top_namespaces':
        sorted(by_namespace.items(), key=lambda x: x[1], reverse=True)[:10]
    }


def main():
    """Основная функция анализа"""
    audit_log_path = 'audit.log'
    output_json_path = 'audit-extract.json'

    print("Загрузка событий из audit.log...")
    events = load_audit_events(audit_log_path)
    total_events = len(events)
    print(f"Загружено событий: {total_events}")

    print("\nАнализ событий...")
    all_findings = []
    for i, event in enumerate(events, 1):
        if i % 500 == 0:
            print(f"  Обработано: {i}/{total_events}")

        findings = analyze_event(event)
        all_findings.extend(findings)

    print(f"\nНайдено подозрительных событий: {len(all_findings)}")

    # Сортировка по severity
    all_findings.sort(
        key=lambda x: (SEVERITY_PRIORITY[x['severity']], x['timestamp']))

    # Генерация сводки
    summary = generate_summary(all_findings)

    # Вывод статистики в консоль
    print("\n" + "=" * 60)
    print("СВОДКА ПО УРОВНЯМ КРИТИЧНОСТИ:")
    print("=" * 60)
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = summary['by_severity'].get(severity, 0)
        print(f"  {severity:10s}: {count}")

    print("\n" + "=" * 60)
    print("СВОДКА ПО КАТЕГОРИЯМ:")
    print("=" * 60)
    for category, count in sorted(summary['by_category'].items(),
                                  key=lambda x: x[1],
                                  reverse=True):
        print(f"  {category:25s}: {count}")

    print("\n" + "=" * 60)
    print("ТОП-10 ПОЛЬЗОВАТЕЛЕЙ С ПОДОЗРИТЕЛЬНЫМИ ДЕЙСТВИЯМИ:")
    print("=" * 60)
    for user, count in summary['top_users']:
        print(f"  {user:50s}: {count}")

    print("\n" + "=" * 60)
    print("ТОП-10 NAMESPACES С ПОДОЗРИТЕЛЬНЫМИ ДЕЙСТВИЯМИ:")
    print("=" * 60)
    for namespace, count in summary['top_namespaces']:
        print(f"  {namespace:30s}: {count}")

    # Сохранение в JSONL формате (каждый объект на отдельной строке)
    print(f"\nСохранение результатов в {output_json_path}...")
    with open(output_json_path, 'w', encoding='utf-8') as f:
        # Первая строка - метаданные анализа
        metadata = {
            'type': 'metadata',
            'timestamp':
            datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'total_events': total_events,
            'suspicious_events': len(all_findings)
        }
        f.write(json.dumps(metadata, ensure_ascii=False) + '\n')

        # Вторая строка - сводная статистика
        summary_record = {
            'type': 'summary',
            **summary
        }
        f.write(json.dumps(summary_record, ensure_ascii=False) + '\n')

        # Остальные строки - findings (по одному на строку)
        for finding in all_findings:
            finding_record = {
                'type': 'finding',
                **finding
            }
            f.write(json.dumps(finding_record, ensure_ascii=False) + '\n')

    print("Анализ завершен!")


if __name__ == '__main__':
    main()
