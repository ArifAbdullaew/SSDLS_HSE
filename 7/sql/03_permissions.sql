-- Create limited application user
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cve_app') THEN
    CREATE ROLE cve_app WITH LOGIN PASSWORD 'cve_app_pass';
  END IF;
END
$$;

GRANT CONNECT ON DATABASE cve_db TO cve_app;
GRANT USAGE  ON SCHEMA public TO cve_app;

-- Read + write on all current tables
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO cve_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cve_app;

-- Ensure future tables are also accessible
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE ON TABLES TO cve_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO cve_app;
