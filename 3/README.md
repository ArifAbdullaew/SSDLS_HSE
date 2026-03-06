## Запуск
1) Скопируйте `.env.example` в `.env` и при необходимости поправьте значения.
2) `docker compose up --build`
3) В контейнере `app` запустится CLI и запросит пароль (берётся из `.env`).

## Примеры команд

### Просмотр без фильтра
python app.py view --table cve

### Фильтр по одному/нескольким значениям
python app.py view --table cvss --where version=3.1
python app.py view --table cve --where cve_id=CVE-2024-12345 published_date=2024-06-10

### WHERE IN
python app.py view-in --table package --column name --values '["openssl","zlib"]'

### Обновление одной записи
python app.py update-one --table package_version --id 1 --set version=1.1.1v

### Обновление нескольких записей одним значением
python app.py update-many --table affected_version --column fixed_in_version --value 3.0.12 --where-in-col cve_id --where-in "[1,2,3]"

### Вставка одной строки
python app.py insert-one --table package --values name=nginx

### Комплексная вставка (несколько связанных таблиц)
python app.py insert-cve-related \
  --cve '{"cve_id":"CVE-2025-0002","summary":"New vuln","published_date":"2025-10-01"}' \
  --cvss '[{"version":"3.1","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","score":9.8}]' \
  --affected '[{"package_version_id":1,"fixed_in_version":"3.0.12"}]'

### Множественная вставка в одну таблицу
python app.py bulk-insert --table reference_link --rows '[{"cve_id":1,"url":"https://example.com/advisory"}]'
