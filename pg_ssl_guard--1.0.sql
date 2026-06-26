\echo Use "CREATE EXTENSION pg_ssl_guard" to load this file. \quit

CREATE FUNCTION pg_ssl_guard_validate(
    client_cidr text,
    role_name name,
    database_name text DEFAULT 'all',
    auth_method text DEFAULT 'scram-sha-256'
) RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ssl_guard_validate'
LANGUAGE C STRICT;

CREATE FUNCTION pg_ssl_guard_apply(
    client_cidr text,
    role_name name,
    database_name text DEFAULT 'all',
    auth_method text DEFAULT 'scram-sha-256',
    require_ssl boolean DEFAULT true
) RETURNS text
AS 'MODULE_PATHNAME', 'pg_ssl_guard_apply'
LANGUAGE C STRICT;

CREATE FUNCTION pg_ssl_guard_remove(
    client_cidr text,
    role_name name,
    database_name text DEFAULT 'all'
) RETURNS integer
AS 'MODULE_PATHNAME', 'pg_ssl_guard_remove'
LANGUAGE C STRICT;

CREATE FUNCTION pg_ssl_guard_reload()
RETURNS boolean
LANGUAGE sql
AS $$ SELECT pg_reload_conf(); $$;

CREATE VIEW pg_ssl_guard_hba_rules AS
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    netmask,
    auth_method,
    options,
    error
FROM pg_hba_file_rules
WHERE type IN ('hostssl', 'hostnossl');

CREATE VIEW pg_ssl_guard_active_ssl AS
SELECT
    a.pid,
    a.usename,
    a.datname,
    a.client_addr,
    s.ssl,
    s.version,
    s.cipher,
    s.bits,
    s.client_dn
FROM pg_stat_activity AS a
LEFT JOIN pg_stat_ssl AS s ON s.pid = a.pid
WHERE a.client_addr IS NOT NULL;
