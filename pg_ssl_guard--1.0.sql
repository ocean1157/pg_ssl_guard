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

CREATE VIEW pg_ssl_guard_ssl_config AS
SELECT
    current_setting('ssl', true)::boolean AS ssl_enabled,
    current_setting('ssl_cert_file', true) AS ssl_cert_file,
    current_setting('ssl_key_file', true) AS ssl_key_file,
    current_setting('ssl_ca_file', true) AS ssl_ca_file,
    current_setting('ssl_crl_file', true) AS ssl_crl_file,
    current_setting('ssl_crl_dir', true) AS ssl_crl_dir,
    current_setting('ssl_min_protocol_version', true) AS ssl_min_protocol_version,
    current_setting('ssl_max_protocol_version', true) AS ssl_max_protocol_version,
    current_setting('ssl_ciphers', true) AS ssl_ciphers,
    current_setting('ssl_prefer_server_ciphers', true)::boolean AS ssl_prefer_server_ciphers,
    current_setting('ssl_dh_params_file', true) AS ssl_dh_params_file,
    current_setting('ssl_passphrase_command', true) AS ssl_passphrase_command,
    current_setting('ssl_passphrase_command_supports_reload', true)::boolean AS ssl_passphrase_command_supports_reload;

CREATE VIEW pg_ssl_guard_ssl_file_status AS
WITH ssl_files(file_item, file_path, required_for_ssl) AS (
    VALUES
        ('ssl_cert_file', current_setting('ssl_cert_file', true), true),
        ('ssl_key_file', current_setting('ssl_key_file', true), true),
        ('ssl_ca_file', current_setting('ssl_ca_file', true), false),
        ('ssl_crl_file', current_setting('ssl_crl_file', true), false),
        ('ssl_dh_params_file', current_setting('ssl_dh_params_file', true), false)
)
SELECT
    f.file_item,
    f.file_path,
    f.required_for_ssl,
    (s.size IS NOT NULL) AS exists,
    s.size,
    s.modification,
    s.isdir AS is_directory
FROM ssl_files AS f
LEFT JOIN LATERAL pg_stat_file(NULLIF(f.file_path, ''), true) AS s
    ON f.file_path IS NOT NULL AND f.file_path <> '';

CREATE VIEW pg_ssl_guard_connection_summary AS
SELECT
    count(*) FILTER (WHERE a.client_addr IS NOT NULL) AS remote_connections,
    count(*) FILTER (WHERE a.client_addr IS NOT NULL AND coalesce(s.ssl, false)) AS ssl_connections,
    count(*) FILTER (WHERE a.client_addr IS NOT NULL AND NOT coalesce(s.ssl, false)) AS non_ssl_connections,
    round(
        100.0 * count(*) FILTER (WHERE a.client_addr IS NOT NULL AND coalesce(s.ssl, false))
        / NULLIF(count(*) FILTER (WHERE a.client_addr IS NOT NULL), 0),
        2
    ) AS ssl_percent,
    count(DISTINCT a.usename) FILTER (WHERE a.client_addr IS NOT NULL) AS remote_users,
    count(DISTINCT a.client_addr) FILTER (WHERE a.client_addr IS NOT NULL) AS remote_client_addresses
FROM pg_stat_activity AS a
LEFT JOIN pg_stat_ssl AS s ON s.pid = a.pid;

CREATE VIEW pg_ssl_guard_cipher_summary AS
SELECT
    s.version,
    s.cipher,
    s.bits,
    count(*) AS connection_count
FROM pg_stat_activity AS a
JOIN pg_stat_ssl AS s ON s.pid = a.pid
WHERE a.client_addr IS NOT NULL
  AND s.ssl
GROUP BY s.version, s.cipher, s.bits
ORDER BY connection_count DESC, s.version, s.cipher;

CREATE VIEW pg_ssl_guard_hba_errors AS
SELECT
    line_number,
    type,
    database,
    user_name,
    address,
    auth_method,
    error
FROM pg_hba_file_rules
WHERE error IS NOT NULL;

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

COMMENT ON VIEW pg_ssl_guard_ssl_config IS
'查看 PostgreSQL SSL 相关参数，包括是否启用 SSL、证书文件、私钥文件、协议版本和加密套件配置。';

COMMENT ON VIEW pg_ssl_guard_ssl_file_status IS
'检查 SSL 相关证书、私钥、CA、CRL 和 DH 参数文件是否存在，以及文件大小和修改时间。';

COMMENT ON VIEW pg_ssl_guard_connection_summary IS
'汇总当前远程连接数量、SSL 连接数量、非 SSL 连接数量、SSL 占比、远程用户数和客户端地址数。';

COMMENT ON VIEW pg_ssl_guard_cipher_summary IS
'按 TLS 协议版本、加密套件和加密位数统计当前 SSL 连接数量。';

COMMENT ON VIEW pg_ssl_guard_hba_errors IS
'查看 pg_hba.conf 中 PostgreSQL 无法解析的规则及错误原因。';
