#!/bin/sh
set -e

echo "=== Vault Setup ==="

# Шаг 4: Включить метод авторизации AppRole
echo "[4] Enabling AppRole auth method..."
vault auth enable approle || echo "AppRole already enabled, skipping."

# Шаг 5: Создать секрет (логин и пароль для БД)
# В dev mode KV v2 уже включён по пути secret/
echo "[5] Writing DB secret to secret/pinger/db ..."
vault kv put secret/pinger/db username=appuser password=secret

# Шаг 6: Создать политику для чтения секрета
echo "[6] Writing pinger-policy ..."
vault policy write pinger-policy - << 'EOF'
path "secret/data/pinger/db" {
  capabilities = ["read"]
}
EOF

# Шаг 7: Создать AppRole для сервиса pinger
echo "[7] Creating AppRole 'pinger' ..."
vault write auth/approle/role/pinger \
  token_policies=pinger-policy \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=0 \
  secret_id_num_uses=0

# Шаг 8: Получить role-id
echo "[8] Reading role-id ..."
ROLE_ID=$(vault read -field=role_id auth/approle/role/pinger/role-id)
echo "Role ID: $ROLE_ID"
echo "$ROLE_ID" > /vault-secrets/role-id

# Генерируем secret-id (для AppRole login в pinger)
echo "Generating secret-id ..."
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/pinger/secret-id)
echo "$SECRET_ID" > /vault-secrets/secret-id

echo "=== Vault Setup Complete ==="
echo "Role ID  : $ROLE_ID"
echo "Secret ID: $SECRET_ID"
