\echo 请使用 "CREATE EXTENSION pg_ssl_guard" 加载此扩展。 \quit

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

COMMENT ON EXTENSION pg_ssl_guard IS '按客户端 CIDR、数据库用户和数据库名管理 PostgreSQL SSL 访问规则';

COMMENT ON FUNCTION pg_ssl_guard_validate(text, name, text, text) IS
'校验客户端 CIDR、登录用户、数据库名和认证方式是否合法，不修改 pg_hba.conf。';

COMMENT ON FUNCTION pg_ssl_guard_apply(text, name, text, text, boolean) IS
'写入或替换插件托管的 SSL 访问策略。client_cidr 为客户端 IP/CIDR，role_name 为登录用户，database_name 为数据库名，auth_method 为认证方式，require_ssl 表示是否强制 SSL。';

COMMENT ON FUNCTION pg_ssl_guard_remove(text, name, text) IS
'删除指定客户端 CIDR、登录用户和数据库名对应的插件托管规则。';

COMMENT ON FUNCTION pg_ssl_guard_reload() IS
'重新加载 PostgreSQL 配置，使 pg_hba.conf 中的新规则生效。';

COMMENT ON VIEW pg_ssl_guard_hba_rules IS
'查看当前 PostgreSQL 识别到的 hostssl 和 hostnossl 访问规则。';

COMMENT ON VIEW pg_ssl_guard_active_ssl IS
'查看当前客户端连接的 SSL 状态、协议版本、加密套件和客户端证书信息。';
