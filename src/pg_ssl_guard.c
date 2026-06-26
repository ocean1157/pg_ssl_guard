#include "postgres.h"

#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/pg_authid.h"
#include "commands/dbcommands.h"
#include "fmgr.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/inet.h"
#include "utils/syscache.h"

#include <ctype.h>
#include <sys/stat.h>
PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(pg_ssl_guard_validate);
PG_FUNCTION_INFO_V1(pg_ssl_guard_apply);
PG_FUNCTION_INFO_V1(pg_ssl_guard_remove);

#define SSL_GUARD_BEGIN "# pg_ssl_guard: begin"
#define SSL_GUARD_END "# pg_ssl_guard: end"
#define SSL_GUARD_MARK "# pg_ssl_guard:"

static const char *allowed_auth_methods[] = {
	"scram-sha-256",
	"cert",
	"md5",
	"password",
	"trust",
	"reject",
	NULL
};

static char *
text_arg_to_cstring(PG_FUNCTION_ARGS, int n)
{
	text *value = PG_GETARG_TEXT_PP(n);
	return text_to_cstring(value);
}

static char *
name_arg_to_cstring(PG_FUNCTION_ARGS, int n)
{
	Name value = PG_GETARG_NAME(n);
	return pstrdup(NameStr(*value));
}

static bool
token_is_simple(const char *value, bool allow_slash_colon)
{
	const unsigned char *p;

	if (value == NULL || value[0] == '\0')
		return false;

	for (p = (const unsigned char *) value; *p; p++)
	{
		if (isalnum(*p) || *p == '_' || *p == '-' || *p == '.')
			continue;
		if (allow_slash_colon && (*p == '/' || *p == ':'))
			continue;
		return false;
	}

	return true;
}

static bool
auth_method_is_allowed(const char *auth_method)
{
	int i;

	for (i = 0; allowed_auth_methods[i] != NULL; i++)
	{
		if (pg_strcasecmp(auth_method, allowed_auth_methods[i]) == 0)
			return true;
	}

	return false;
}

static void
validate_inputs(const char *client_cidr, const char *role_name,
				const char *database_name, const char *auth_method)
{
	Datum inet_value;
	HeapTuple role_tuple;
	Form_pg_authid role_form;

	if (!token_is_simple(client_cidr, true))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("client CIDR contains unsupported characters")));

	if (!token_is_simple(role_name, false))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("role name contains unsupported characters")));

	if (!token_is_simple(database_name, false) && pg_strcasecmp(database_name, "all") != 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("database name contains unsupported characters")));

	if (!auth_method_is_allowed(auth_method))
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("unsupported authentication method \"%s\"", auth_method)));

	inet_value = DirectFunctionCall1(cidr_in, CStringGetDatum(client_cidr));
	(void) inet_value;

	role_tuple = SearchSysCache1(AUTHNAME, CStringGetDatum(role_name));
	if (!HeapTupleIsValid(role_tuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("role \"%s\" does not exist", role_name)));

	role_form = (Form_pg_authid) GETSTRUCT(role_tuple);
	if (!role_form->rolcanlogin)
	{
		ReleaseSysCache(role_tuple);
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("role \"%s\" is not a login role", role_name)));
	}
	ReleaseSysCache(role_tuple);

	if (pg_strcasecmp(database_name, "all") != 0 &&
		get_database_oid(database_name, true) == InvalidOid)
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_DATABASE),
				 errmsg("database \"%s\" does not exist", database_name)));
}

static char *
read_whole_file(const char *path, long *size_out)
{
	FILE *file;
	StringInfoData data;
	char buffer[8192];
	size_t read_size;

	file = AllocateFile(path, "r");
	if (file == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open \"%s\" for reading: %m", path)));

	initStringInfo(&data);
	while ((read_size = fread(buffer, 1, sizeof(buffer), file)) > 0)
		appendBinaryStringInfo(&data, buffer, read_size);

	if (ferror(file))
	{
		FreeFile(file);
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not read \"%s\": %m", path)));
	}

	FreeFile(file);
	*size_out = data.len;
	return data.data;
}

static void
write_whole_file(const char *path, const char *content, int len)
{
	FILE *file;
	char *tmp_path;
	struct stat st;
	bool have_stat;

	tmp_path = psprintf("%s.pg_ssl_guard.tmp", path);
	have_stat = (stat(path, &st) == 0);

	file = AllocateFile(tmp_path, "w");
	if (file == NULL)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not open \"%s\" for writing: %m", tmp_path)));

	if (fwrite(content, 1, len, file) != (size_t) len)
	{
		FreeFile(file);
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not write \"%s\": %m", tmp_path)));
	}

	if (FreeFile(file) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not close \"%s\": %m", tmp_path)));

	if (have_stat && chmod(tmp_path, st.st_mode) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not set permissions on \"%s\": %m", tmp_path)));

	if (rename(tmp_path, path) != 0)
		ereport(ERROR,
				(errcode_for_file_access(),
				 errmsg("could not replace \"%s\": %m", path)));
}

static bool
line_matches_rule(const char *line, const char *client_cidr,
				  const char *role_name, const char *database_name)
{
	char *needle = psprintf(" user=%s db=%s cidr=%s ",
							role_name, database_name, client_cidr);
	bool matches = strstr(line, needle) != NULL;

	pfree(needle);
	return matches;
}

static char *
make_hba_line(const char *client_cidr, const char *role_name,
			  const char *database_name, const char *auth_method,
			  bool require_ssl)
{
	const char *type = require_ssl ? "hostssl" : "hostnossl";
	const char *reject_type = require_ssl ? "hostnossl" : "hostssl";

	return psprintf("%s user=%s db=%s cidr=%s ssl=%s\n"
					"%s %s %s %s reject\n"
					"%s %s %s %s %s\n",
					SSL_GUARD_MARK,
					role_name,
					database_name,
					client_cidr,
					require_ssl ? "require" : "disable",
					reject_type,
					database_name,
					role_name,
					client_cidr,
					type,
					database_name,
					role_name,
					client_cidr,
					auth_method);
}

static int
rewrite_hba(const char *client_cidr, const char *role_name,
			const char *database_name, const char *auth_method,
			bool require_ssl, bool add_rule)
{
	const char *hba_file;
	char *original;
	char *cursor;
	long original_size;
	bool in_block = false;
	bool saw_block = false;
	bool added = false;
	int skip_managed_lines = 0;
	int removed = 0;
	StringInfoData managed;
	StringInfoData rest;
	StringInfoData output;
	char *new_line = NULL;

	hba_file = GetConfigOptionByName("hba_file", NULL, false);
	original = read_whole_file(hba_file, &original_size);

	initStringInfo(&managed);
	initStringInfo(&rest);
	initStringInfo(&output);

	if (add_rule)
		new_line = make_hba_line(client_cidr, role_name, database_name,
								 auth_method, require_ssl);

	cursor = original;
	while (*cursor != '\0')
	{
		char *line_start = cursor;
		char *line_end = strchr(cursor, '\n');
		int line_len;
		char *line_copy;

		if (line_end == NULL)
		{
			line_len = strlen(line_start);
			cursor = line_start + line_len;
		}
		else
		{
			line_len = line_end - line_start + 1;
			cursor = line_end + 1;
		}

		line_copy = pnstrdup(line_start, line_len);

		if (strncmp(line_copy, SSL_GUARD_BEGIN, strlen(SSL_GUARD_BEGIN)) == 0)
		{
			in_block = true;
			saw_block = true;
			pfree(line_copy);
			continue;
		}

		if (strncmp(line_copy, SSL_GUARD_END, strlen(SSL_GUARD_END)) == 0)
		{
			in_block = false;
			if (add_rule && !added)
			{
				appendStringInfoString(&managed, new_line);
				added = true;
			}
			pfree(line_copy);
			continue;
		}

		if (in_block)
		{
			if (skip_managed_lines > 0)
			{
				skip_managed_lines--;
				pfree(line_copy);
				continue;
			}

			if (line_matches_rule(line_copy, client_cidr, role_name, database_name))
			{
				removed++;
				skip_managed_lines = 2;
				pfree(line_copy);
				continue;
			}
			appendStringInfoString(&managed, line_copy);
		}
		else
			appendStringInfoString(&rest, line_copy);

		pfree(line_copy);
	}

	if (in_block)
		ereport(ERROR,
				(errcode(ERRCODE_CONFIG_FILE_ERROR),
				 errmsg("unterminated pg_ssl_guard block in pg_hba.conf")));

	if (add_rule && !added)
	{
		appendStringInfoString(&managed, new_line);
		added = true;
	}

	if (managed.len > 0 || saw_block || add_rule)
	{
		appendStringInfoString(&output, SSL_GUARD_BEGIN "\n");
		appendBinaryStringInfo(&output, managed.data, managed.len);
		appendStringInfoString(&output, SSL_GUARD_END "\n\n");
	}
	appendBinaryStringInfo(&output, rest.data, rest.len);

	write_whole_file(hba_file, output.data, output.len);

	CommandCounterIncrement();
	return removed;
}

Datum
pg_ssl_guard_validate(PG_FUNCTION_ARGS)
{
	char *client_cidr = text_arg_to_cstring(fcinfo, 0);
	char *role_name = name_arg_to_cstring(fcinfo, 1);
	char *database_name = text_arg_to_cstring(fcinfo, 2);
	char *auth_method = text_arg_to_cstring(fcinfo, 3);

	validate_inputs(client_cidr, role_name, database_name, auth_method);
	PG_RETURN_BOOL(true);
}

Datum
pg_ssl_guard_apply(PG_FUNCTION_ARGS)
{
	char *client_cidr = text_arg_to_cstring(fcinfo, 0);
	char *role_name = name_arg_to_cstring(fcinfo, 1);
	char *database_name = text_arg_to_cstring(fcinfo, 2);
	char *auth_method = text_arg_to_cstring(fcinfo, 3);
	bool require_ssl = PG_GETARG_BOOL(4);
	int replaced;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_ssl_guard_apply requires superuser privileges")));

	validate_inputs(client_cidr, role_name, database_name, auth_method);
	replaced = rewrite_hba(client_cidr, role_name, database_name, auth_method,
						   require_ssl, true);

	PG_RETURN_TEXT_P(cstring_to_text(psprintf(
		"pg_ssl_guard wrote %s rule for role \"%s\" from \"%s\"; replaced %d existing managed rule(s). Run SELECT pg_ssl_guard_reload();",
		require_ssl ? "hostssl" : "hostnossl",
		role_name,
		client_cidr,
		replaced)));
}

Datum
pg_ssl_guard_remove(PG_FUNCTION_ARGS)
{
	char *client_cidr = text_arg_to_cstring(fcinfo, 0);
	char *role_name = name_arg_to_cstring(fcinfo, 1);
	char *database_name = text_arg_to_cstring(fcinfo, 2);
	int removed;

	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("pg_ssl_guard_remove requires superuser privileges")));

	validate_inputs(client_cidr, role_name, database_name, "scram-sha-256");
	removed = rewrite_hba(client_cidr, role_name, database_name,
						   "scram-sha-256", true, false);

	PG_RETURN_INT32(removed);
}
