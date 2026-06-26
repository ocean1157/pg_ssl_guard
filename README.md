# pg_ssl_guard

`pg_ssl_guard` is a PostgreSQL 16 C extension for managing SSL access rules for a specific client CIDR and login role.

It writes a managed block at the top of `pg_hba.conf` so SSL rules are evaluated before broader host rules. The extension is intentionally superuser-only because changing `pg_hba.conf` controls database access.

## Why this name

The project name is `pg_ssl_guard`: short, PostgreSQL-specific, and focused on guarding client access with SSL policy.

## Build and install

```sh
make PG_CONFIG=/path/to/pg_config
sudo make PG_CONFIG=/path/to/pg_config install
```

Then in PostgreSQL:

```sql
CREATE EXTENSION pg_ssl_guard;
```

## Usage

Require SSL for user `app_user` from `10.0.0.141/32`:

```sql
SELECT pg_ssl_guard_apply('10.0.0.141/32', 'app_user', 'all', 'scram-sha-256', true);
SELECT pg_ssl_guard_reload();
```

Remove that managed rule:

```sql
SELECT pg_ssl_guard_remove('10.0.0.141/32', 'app_user', 'all');
SELECT pg_ssl_guard_reload();
```

Validate inputs before applying:

```sql
SELECT pg_ssl_guard_validate('10.0.0.141/32', 'app_user');
```

Check configured HBA rules and active SSL sessions:

```sql
SELECT * FROM pg_ssl_guard_hba_rules;
SELECT * FROM pg_ssl_guard_active_ssl WHERE usename = 'app_user';
```

## Behavior

- `require_ssl = true` writes `hostnossl ... reject` followed by `hostssl ... <auth_method>`.
- `require_ssl = false` writes `hostssl ... reject` followed by `hostnossl ... <auth_method>`.
- Rules are stored between `# pg_ssl_guard: begin` and `# pg_ssl_guard: end`.
- Existing managed rules for the same database, role, and CIDR are replaced.
- The extension validates CIDR syntax, role names, database names, and common authentication methods.

Important: a `hostssl` rule only works when PostgreSQL itself has SSL enabled with valid `ssl_cert_file` and `ssl_key_file` settings.
