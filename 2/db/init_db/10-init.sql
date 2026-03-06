DO $$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'appuser') THEN
      CREATE ROLE appuser LOGIN PASSWORD 'app_password';
   END IF;
END$$;

REVOKE ALL ON DATABASE appdb FROM PUBLIC;
GRANT CONNECT ON DATABASE appdb TO appuser;

\connect appdb

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO appuser;