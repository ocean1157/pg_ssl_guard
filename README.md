# pg_ssl_guard

`pg_ssl_guard` 是一个 PostgreSQL 16 C 扩展，用于按“客户端 IP/CIDR + 数据库用户 + 数据库名”管理 SSL 访问策略。

它会在 `pg_hba.conf` 文件顶部写入一段由插件托管的规则块，让精确的 SSL 访问规则优先于后面更宽泛的 `host` 规则生效。由于修改 `pg_hba.conf` 会直接影响数据库访问权限，本扩展要求超级用户执行安装和配置操作。

## 项目名称说明

项目名 `pg_ssl_guard` 的含义是“PostgreSQL SSL 访问守卫”。它强调两个核心点：

- `pg`：面向 PostgreSQL。
- `ssl_guard`：对指定客户端和用户的 SSL 访问策略进行守护和管控。

## 编译安装

在 PostgreSQL 16 服务器上执行：

```sh
make PG_CONFIG=/path/to/pg_config
make PG_CONFIG=/path/to/pg_config install
```

如果你的 PostgreSQL 16 环境通过 `.bash_profile16` 加载，可以这样执行：

```sh
source ~/.bash_profile16
make PG_CONFIG=$(which pg_config)
make PG_CONFIG=$(which pg_config) install
```

进入数据库后创建扩展：

```sql
CREATE EXTENSION pg_ssl_guard;
```

## 常用示例

要求用户 `app_user` 从客户端 `10.0.0.141/32` 访问时必须使用 SSL：

```sql
SELECT pg_ssl_guard_apply('10.0.0.141/32', 'app_user', 'all', 'scram-sha-256', true);
SELECT pg_ssl_guard_reload();
```

删除这条由插件管理的规则：

```sql
SELECT pg_ssl_guard_remove('10.0.0.141/32', 'app_user', 'all');
SELECT pg_ssl_guard_reload();
```

只校验参数是否合法，不写入配置：

```sql
SELECT pg_ssl_guard_validate('10.0.0.141/32', 'app_user');
```

检查 SSL 相关 HBA 规则和当前连接的 SSL 状态：

```sql
SELECT * FROM pg_ssl_guard_hba_rules;
SELECT * FROM pg_ssl_guard_active_ssl WHERE usename = 'app_user';
```

## 函数说明

### pg_ssl_guard_apply

```sql
pg_ssl_guard_apply(
    client_cidr text,
    role_name name,
    database_name text DEFAULT 'all',
    auth_method text DEFAULT 'scram-sha-256',
    require_ssl boolean DEFAULT true
) RETURNS text
```

写入或替换一条由插件管理的访问策略。

参数说明：

- `client_cidr`：客户端 IP 或网段，使用 CIDR 格式。例如 `10.0.0.141/32` 表示单个客户端，`10.0.0.0/24` 表示一个网段。
- `role_name`：访问数据库的登录用户。该用户必须存在，并且必须具备登录能力。
- `database_name`：允许访问的数据库名。默认值 `all` 表示所有数据库；指定具体库名时，该数据库必须存在。
- `auth_method`：认证方式，默认 `scram-sha-256`。当前支持 `scram-sha-256`、`cert`、`md5`、`password`、`trust`、`reject`。
- `require_ssl`：是否要求 SSL。`true` 表示强制 SSL；`false` 表示明确使用非 SSL。

返回值说明：

- 返回一段文本，说明写入的规则类型、目标用户、客户端 CIDR，以及替换了几条旧规则。

### pg_ssl_guard_remove

```sql
pg_ssl_guard_remove(
    client_cidr text,
    role_name name,
    database_name text DEFAULT 'all'
) RETURNS integer
```

删除指定客户端、用户和数据库对应的插件托管规则。

参数说明：

- `client_cidr`：要删除规则对应的客户端 IP 或网段。
- `role_name`：要删除规则对应的登录用户。
- `database_name`：要删除规则对应的数据库名，默认 `all`。

返回值说明：

- 返回删除的规则数量。

### pg_ssl_guard_validate

```sql
pg_ssl_guard_validate(
    client_cidr text,
    role_name name,
    database_name text DEFAULT 'all',
    auth_method text DEFAULT 'scram-sha-256'
) RETURNS boolean
```

校验参数是否合法，不修改 `pg_hba.conf`。

校验内容：

- `client_cidr` 是否为合法 CIDR。
- `role_name` 是否存在，且是否为可登录用户。
- `database_name` 为具体数据库名时，该数据库是否存在。
- `auth_method` 是否属于受支持的认证方式。

返回值说明：

- 参数全部合法时返回 `true`。
- 参数非法时抛出 PostgreSQL 错误。

### pg_ssl_guard_reload

```sql
pg_ssl_guard_reload() RETURNS boolean
```

调用 `pg_reload_conf()` 重新加载 PostgreSQL 配置。

说明：

- `pg_ssl_guard_apply` 和 `pg_ssl_guard_remove` 只负责写入 `pg_hba.conf`。
- 写入后需要执行 `pg_ssl_guard_reload()`，新规则才会被 PostgreSQL 加载。

## 视图说明

### pg_ssl_guard_hba_rules

查看当前 PostgreSQL 识别到的 SSL 相关 HBA 规则。

字段说明：

- `line_number`：规则在 `pg_hba.conf` 中的行号。
- `type`：规则类型。常见值包括 `hostssl` 和 `hostnossl`。
- `database`：规则适用的数据库。
- `user_name`：规则适用的数据库用户。
- `address`：客户端地址或网段。
- `netmask`：网络掩码。
- `auth_method`：认证方式，例如 `scram-sha-256`、`cert`、`reject`。
- `options`：HBA 规则附加选项。
- `error`：规则解析错误。如果为空，表示该行规则解析正常。

### pg_ssl_guard_active_ssl

查看当前客户端连接是否使用 SSL。

字段说明：

- `pid`：后端进程 ID。
- `usename`：当前连接使用的数据库用户。
- `datname`：当前连接访问的数据库。
- `client_addr`：客户端 IP 地址。
- `ssl`：是否使用 SSL。`true` 表示 SSL 连接，`false` 表示非 SSL 连接。
- `version`：SSL/TLS 协议版本。
- `cipher`：SSL/TLS 加密套件。
- `bits`：加密位数。
- `client_dn`：客户端证书 DN。只有使用客户端证书时才可能有值。

## 规则写入行为

- `require_ssl = true` 时，插件会先写入 `hostnossl ... reject`，再写入 `hostssl ... <auth_method>`。这样可以阻止同一客户端和用户通过非 SSL 规则绕过限制。
- `require_ssl = false` 时，插件会先写入 `hostssl ... reject`，再写入 `hostnossl ... <auth_method>`。
- 插件管理的规则位于 `# pg_ssl_guard: begin` 和 `# pg_ssl_guard: end` 之间。
- 对同一个 `database_name + role_name + client_cidr` 重复执行 `pg_ssl_guard_apply` 时，会替换旧规则。

## 注意事项

- `hostssl` 规则只有在 PostgreSQL 已开启 SSL 时才会生效。
- PostgreSQL 需要配置有效的 `ssl_cert_file` 和 `ssl_key_file`。
- 本扩展会修改 `pg_hba.conf`，请先确认当前 PostgreSQL 运行用户对该文件有写权限。
- 建议先执行 `pg_ssl_guard_validate` 校验参数，再执行 `pg_ssl_guard_apply`。
