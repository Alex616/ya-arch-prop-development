# RBAC в Kubernetes — PropDevelopment

| Роль | Права роли | Группы пользователей |
| --- | --- | --- |
| `sales-developer` | get, list, watch, create, update, patch на Deployments, Pods, Services, ConfigMaps в namespace `sales`; get, list на Secrets (кроме токенов гос.сервисов) | Разработчики домена продаж (vitrina, client-tour-app, client-mart-app, client-crm-app, client-mart-estate-app) |
| `housing-developer` | get, list, watch, create, update, patch на Deployments, Pods, Services, ConfigMaps в namespace `housing`; get, list на Secrets (кроме финансовых секретов) | Разработчики домена ЖКУ (tenant-core-app, CRM собственников, мобильное приложение) |
| `finance-developer` | get, list, watch, create, update, patch на Deployments, Pods, Services, ConfigMaps в namespace `finance`; get, list на Secrets только в `finance` namespace | Разработчики домена финансов (accountant-service-1) |
| `data-developer` | get, list, watch, create, update, patch на Deployments, Pods, Services, ConfigMaps в namespace `data`; get, list на PersistentVolumeClaims | Разработчики домена данных (хранилище, BI, отчётность) |
| `devops-engineer` | get, list, watch, create, update, patch, delete на Deployments, StatefulSets, DaemonSets, Services, Ingress, ConfigMaps во всех namespace; управление Nodes, PersistentVolumes на уровне кластера; get на Secrets | DevOps-инженеры всех команд |
| `security-officer` | get, list, watch на все ресурсы во всех namespace (read-only); get, list на Secrets; управление NetworkPolicy, PodSecurityPolicy; просмотр audit logs | Специалист по ИБ |
| `ops-readonly` | get, list, watch на Pods, Deployments, Services, Events, Logs в своём namespace | Инженеры по эксплуатации (операционный мониторинг без права изменений) |
| `partner-smart-home` | get, list на ConfigMaps с настройками партнёрских интеграций в namespace `integrations`; create, update на Secrets с именем `partner-smart-home-*` (ротация токенов) | Сервисные аккаунты интеграций «Умный дом» (домофон, шлагбаум) |
| `product-owner-readonly` | get, list, watch на Pods, Deployments, Services, Events в namespace своего домена | Владельцы продуктов всех доменов (мониторинг статуса сервисов без права изменений) |
| `cluster-admin` | полный доступ ко всем ресурсам кластера | Ведущие DevOps-инженеры, ответственные за инфраструктуру (не более 2–3 человек) |
