/*
 * mod_ldap_userdir - LDAP UserDir module for the Apache web server
 * Copyright 1999, 2000-5, John Morrissey <jwm@horde.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307, USA.
 *
 *
 * Furthermore, John Morrissey gives permission to link this program with
 * OpenSSL, and distribute the resulting executable, without including the
 * source code for OpenSSL in the source distribution.
 */

/*
 * mod_ldap_userdir v1.1.8
 *
 * Description: A module for the Apache web server that performs UserDir
 * (home directory) lookups from an LDAP directory.
 *
 * Example (request for /~bar/one/two.html):
 *
 * LDAPUserDir public_html       -> ~bar/public_html/one/two.html
 * LDAPUserDir /usr/web          -> /usr/web/bar/one/two.html
 * LDAPUserDir /home/ * /www     -> /home/bar/www/one/two.html
 *       NOTE: these ^ ^ spaces are here to allow this to work in a C-style
 *             comment; they should not be included in your configuration.
 * LDAPUserDir http://x/users/ * -> (302) http://x/users/bar/one/two.html
 *       NOTE:           this ^ space is here to allow this to work in a
 *             C-style comment; they should not be included in your
 *             configuration.
 * LDAPUserDir http://x/ * /y    -> (302) http://x/bar/y/one/two.html
 *	     NOTE:    these ^ ^ spaces are here to allow this to work in a
 *             C-style comment; they should not be included in your
 *             configuration.
 *
 * You can use multiple entries, to specify alternate user
 * directories (a la DirectoryIndex). For example:
 *
 * LDAPUserDir public_html public_www
 * LDAPUserDir public_html /usr/web http://www.xyz.com/users
 */


#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#ifdef STANDARD20_MODULE_STUFF
# define APR_WANT_STRFUNC
# include "apr_want.h"
# include "apr_strings.h"
# include "apr_hash.h"
# include <time.h>
# define AP_POOL apr_pool_t
# define AP_PSTRDUP apr_pstrdup
# define AP_PSTRCAT apr_pstrcat
# define AP_PCALLOC apr_pcalloc
# define AP_STRSTR ap_strstr
# define AP_STRSTR_C ap_strstr_c
# define AP_STRCHR_C ap_strchr_c
# define AP_TABLE_SETN apr_table_setn
# if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
#  define HAVE_UNIX_SUEXEC
#  include "unixd.h"  /* Contains the suexec_identity hook used on Unix */
# endif
#else /* STANDARD20_MODULE_STUFF */
# define AP_POOL pool
# define AP_PSTRDUP ap_pstrdup
# define AP_PSTRCAT ap_pstrcat
# define AP_PCALLOC ap_pcalloc
# define AP_STRSTR strstr
# define AP_STRSTR_C strstr
# define AP_STRCHR_C strchr
# define AP_TABLE_SETN ap_table_setn
# if !defined(NETWARE)
#  include <sys/types.h>
# endif
# include <sys/stat.h>
# if !defined(WIN32)
#  include <unistd.h>
# endif
#endif /* STANDARD20_MODULE_STUFF */

#include <lber.h>
#include <ldap.h>

/* Thanks, Sun. */
#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#ifdef STANDARD20_MODULE_STUFF
module AP_MODULE_DECLARE_DATA ldap_userdir_module;
#else
module MODULE_VAR_EXPORT ldap_userdir_module;
#endif

typedef struct ldap_userdir_config {
	char *userdir;
	int enabled;
#ifdef TLS
	int use_tls;
#endif
	char *server, *ldap_dn, *dn_pass,
	     *basedn, *filter_template, *home_attr;
	int search_scope, cache_timeout;

#ifdef STANDARD20_MODULE_STUFF
	apr_hash_t *homedirHt;
#endif /* STANDARD20_MODULE_STUFF */
} ldap_userdir_config;

#ifdef STANDARD20_MODULE_STUFF
struct hash_entry {
	time_t inserted_at;
	char *homedir;
};
#endif /* STANDARD20_MODULE_STUFF */

static LDAP *ld = NULL;


static void *
create_ldap_userdir_config(AP_POOL *p, server_rec *s)
{
	ldap_userdir_config *newcfg = (ldap_userdir_config *) AP_PCALLOC(p, sizeof(ldap_userdir_config));

	newcfg->userdir = "public_html";
	newcfg->search_scope = LDAP_SCOPE_SUBTREE;
	newcfg->home_attr = "homeDirectory";
	newcfg->cache_timeout = 300;

#ifdef STANDARD20_MODULE_STUFF
	newcfg->homedirHt = apr_hash_make(p);
#endif /* STANDARD20_MODULE_STUFF */

	return (void *)newcfg;
}

static const char *
set_ldap_user_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config (cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDir must be supplied with the public subdirectory in users' home directories (e.g., 'public_html').";
	}

	s_cfg->enabled = 1;
	s_cfg->userdir = AP_PSTRDUP(cmd->pool, arg);

	return NULL;
}

static const char *
set_server(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirServer must be supplied with the name of an LDAP server.";
	}

	s_cfg->server = AP_PSTRDUP(cmd->pool, arg);
	return NULL;
}

static const char *
set_ldap_dninfo(cmd_parms *cmd, void *dummy,
                const char *dn, const char *pass)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(dn) == 0) {
		return "LDAPUserDirDNInfo must be supplied with a LDAP DN to bind as.";
	}
	if (strlen(pass) == 0) {
		return "LDAPUserDirDNInfo must be supplied with a password to bind with.";
	}

	s_cfg->ldap_dn     = (char *)dn;
	s_cfg->dn_pass = (char *)pass;

	return NULL;
}

static const char *
set_basedn(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirBaseDN must be supplied with the LDAP base DN to use for UserDir lookups.";
	}

	s_cfg->basedn = AP_PSTRDUP(cmd->pool, arg);
	return NULL;
}

static const char *
set_filter_template(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirFilter must be supplied with a filter template to use for LDAP UserDir lookups.";
	}

	s_cfg->filter_template = AP_PSTRDUP(cmd->pool, arg);
	return NULL;
}

static const char *
set_search_scope(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirSearchScope must be supplied with a search scope (\"onelevel\" or \"subtree\")";
	}

	if (strcasecmp(arg, "onelevel") == 0) {
		s_cfg->search_scope = LDAP_SCOPE_ONELEVEL;
		return NULL;
	} else if (strcasecmp(arg, "subtree") == 0) {
		s_cfg->search_scope = LDAP_SCOPE_SUBTREE;
		return NULL;
	}

	return "LDAPUserDirSearchScope must be either \"onelevel\" or \"subtree\".";
}

static const char *
set_use_tls(cmd_parms *cmd, void *dummy, int arg)
{
#ifdef TLS
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);
	s_cfg->use_tls = arg;
	return NULL;
#else
	return "You must recompile mod_ldap_userdir to enable TLS/SSL support!";
#endif /* TLS */
}

static const char *
set_home_attr(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirHomeAttribute must be supplied with an attribute name, such as \"homeDirectory\"";
	}

	s_cfg->home_attr = AP_PSTRDUP(cmd->pool, arg);
	return NULL;
}

static const char *
set_cache_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);
	char *invalid_char = NULL;

	s_cfg->cache_timeout = strtol(arg, &invalid_char, 10);
	if (invalid_char != NULL) {
		return "LDAPUserDirCacheTimeout must be supplied with a numeric cache timeout.";
	}
	return NULL;
}

#ifdef STANDARD20_MODULE_STUFF
static int
init_ldap_userdir(apr_pool_t *pconf, apr_pool_t *plog,
                  apr_pool_t *ptemp, server_rec *s)
{
	ap_add_version_component(pconf, "mod_ldap_userdir/1.1.8");
	return OK;
}
#else /* STANDARD20_MODULE_STUFF */
static void
init_ldap_userdir(server_rec *s, AP_POOL *p)
{
	ap_add_version_component("mod_ldap_userdir/1.1.8");
}
#endif /* STANDARD20_MODULE_STUFF */

static int
connect_ldap_userdir(const ldap_userdir_config *s_cfg)
{
	int ret, sizelimit = 2;

	if ((ld = ldap_init(s_cfg->server, LDAP_PORT)) == NULL) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_init() to %s failed: %s", s_cfg->server, strerror(errno));
#else
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: ldap_init() to %s failed: %s", s_cfg->server, strerror(errno));
#endif
		return -1;
	}

#ifdef TLS
	if (s_cfg->use_tls) {
		int version = LDAP_VERSION3;

		if ((ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version)) != LDAP_OPT_SUCCESS) {
#ifdef STANDARD20_MODULE_STUFF
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: Setting LDAP version option failed: %s", ldap_err2string(ret));
#else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: Setting LDAP version option failed: %s", ldap_err2string(ret));
#endif
			ldap_unbind(ld);
			ld = NULL;
			return -1;
		}

		if ((ret = ldap_start_tls_s(ld, NULL, NULL)) != LDAP_SUCCESS) {
#ifdef STANDARD20_MODULE_STUFF
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: Starting TLS failed: %s", ldap_err2string(ret));
#else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: Starting TLS failed: %s", ldap_err2string(ret));
#endif
			ldap_unbind(ld);
			ld = NULL;
			return -1;
		}
	}
#endif /* TLS */

	if ((ret = ldap_simple_bind_s(ld, s_cfg->ldap_dn, s_cfg->dn_pass)) != LDAP_SUCCESS) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_simple_bind() as %s failed: %s", s_cfg->ldap_dn, ldap_err2string(ret));
#else
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: ldap_simple_bind() as %s failed: %s", s_cfg->ldap_dn, ldap_err2string(ret));
#endif
		return -1;
	}

	/* I couldn't think of a better way to do this without having autoconf
	 * jump through hoops to detect whether ldap_set_option is present.
	 * I think this works fairly well, though, as we're sure to need
	 * LDAP_OPT_SIZELIMIT to use ldap_set_option in this case. :-)
	 */
#ifdef LDAP_OPT_SIZELIMIT
	if ((ret = ldap_set_option(ld, LDAP_OPT_SIZELIMIT, (void *)&sizelimit)) != LDAP_OPT_SUCCESS)
#ifdef STANDARD20_MODULE_STUFF
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_set_option() unable to set query size limit to 2 entries: %s", ldap_err2string(ret));
#else /* STANDARD20_MODULE_STUFF */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: ldap_set_option() unable to set query size limit to 2 entries: %s", ldap_err2string(ret));
#endif /* STANDARD20_MODULE_STUFF */
#else /* LDAP_OPT_SIZELIMIT */
	ld->ld_sizelimit = sizelimit;
#endif /* LDAP_OPT_SIZELIMIT */

	return 1;
}

static void
#ifdef STANDARD20_MODULE_STUFF
child_init_ldap_userdir(apr_pool_t *p, server_rec *s)
#else
child_init_ldap_userdir(server_rec *s, AP_POOL *p)
#endif
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(s->module_config, &ldap_userdir_module);

	if (!s_cfg->enabled) {
		return;
	}

	(void) connect_ldap_userdir(s_cfg);
}

static char *
generate_filter(AP_POOL *p, char *template, const char *entity)
{
	char *filter, *pos;
	int num_escapes = 0, i = 0, j = 0;

	pos = template;
	while ((pos = AP_STRSTR(pos + 2, "%v")) != NULL) {
		++num_escapes;
	}

	/* -2 for the %v, +1 for the NULL */
	filter = AP_PCALLOC(p, strlen(template) - (num_escapes * 2) + (num_escapes * strlen(entity)) + 1);

	while (template[i] != '\0') {
		if (template[i] == '%' && template[i + 1] == 'v') {
			strcat(filter, entity);
			j += strlen(entity);
			i += 2;
		} else {
			filter[j++] = template[i++];
		}
	}

	return filter;
}

static char *
cache_fetch(const ldap_userdir_config *s_cfg, const char *username)
{
	struct hash_entry *cached;

	/* A cache timeout of 0 disables caching. */
	if (s_cfg->cache_timeout == 0) {
		return NULL;
	}

	cached = apr_hash_get(s_cfg->homedirHt, username, APR_HASH_KEY_STRING);
	if (cached == NULL) {
		return NULL;
	}

	/* If this entry is still valid, return it. Otherwise, expire the
	 * stale entry.
	 */
	if (cached->inserted_at + s_cfg->cache_timeout > time(NULL)) {
		return cached->homedir;
	}

	free(cached->homedir);
	free(cached);
	apr_hash_set(s_cfg->homedirHt, username, APR_HASH_KEY_STRING, NULL);
	return NULL;
}

void
cache_set(const ldap_userdir_config *s_cfg,
          const char *username, const char *homedir)
{
	struct hash_entry *cached;

	/* A cache timeout of 0 disables caching. */
	if (s_cfg->cache_timeout == 0) {
		return;
	}

	cached = (struct hash_entry *) malloc(sizeof(struct hash_entry));
	if (cached == NULL) {
		return;
	}
	cached->homedir = strdup(homedir);
	if (cached->homedir == NULL) {
		return;
	}
	cached->inserted_at = time(NULL);
	apr_hash_set(s_cfg->homedirHt, username, APR_HASH_KEY_STRING, cached);
}

static const char *
get_ldap_homedir(const ldap_userdir_config *s_cfg, request_rec *r,
                 const char *username)
{
	char *filter, **values, *homedir,
	     *attrs[] = {s_cfg->home_attr, NULL};
	int ret;
	LDAPMessage *result, *e;

#ifdef STANDARD20_MODULE_STUFF
	homedir = cache_fetch(s_cfg, username);
	if (homedir != NULL) {
		return homedir;
	}
#endif /* STANDARD20_MODULE_STUFF */

	/* If we haven't even connected yet, try to connect. If we still can't
	   connect, give up. */
	if (ld == NULL) {
		if (connect_ldap_userdir(s_cfg) != 1) {
			return NULL;
		}
	}

	if (s_cfg->filter_template && *(s_cfg->filter_template)) {
		filter = generate_filter(r->pool, s_cfg->filter_template, username);
	} else {
		filter = generate_filter(r->pool, "(&(uid=%v)(objectClass=posixAccount))", username);
	}

	if ((ret = ldap_search_s(ld, s_cfg->basedn, s_cfg->search_scope, filter, attrs, 0, &result)) != LDAP_SUCCESS) {
		/* If the LDAP server went away, try to reconnect. If the reconnect
		   fails, give up and log accordingly. */
		if (ret == LDAP_SERVER_DOWN) {
			ldap_unbind(ld);

			if (connect_ldap_userdir(s_cfg) != 1) {
#ifdef STANDARD20_MODULE_STUFF
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: LDAP server went away, couldn't reconnect. Declining request.");
#else
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: LDAP server went away, couldn't reconnect. Declining request.");
#endif
				ld = NULL;
				return NULL;
			}

			if ((ret = ldap_search_s(ld, s_cfg->basedn, s_cfg->search_scope, filter, attrs, 0, &result)) != LDAP_SUCCESS) {
#ifdef STANDARD20_MODULE_STUFF
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_search_s() failed: %s", ldap_err2string(ret));
#else
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_search_s() failed: %s", ldap_err2string(ret));
#endif
				return NULL;
			}
		} else {
#ifdef STANDARD20_MODULE_STUFF
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_search_s() failed: %s", ldap_err2string(ret));
#else
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_search_s() failed: %s", ldap_err2string(ret));
#endif
			return NULL;
		}
	}

	if ((ret = ldap_count_entries(ld, result)) > 1) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: found too many entries (%d entries) for query, expecting 1 entry. Ignoring LDAP results.", ret);
#else
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: found too many entries (%d entries) for query, expecting 1 entry. Ignoring LDAP results.", ret);
#endif
		ldap_msgfree(result);
		return NULL;
	} else if (ret < 1) {
		/* We didn't find any users, don't bother calling ldap_first_entry(). */
		return NULL;
	}

	if ((e = ldap_first_entry(ld, result)) == NULL) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_first_entry() failed: %s", ldap_err2string(ldap_result2error(ld, result, 0)));
#else
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_first_entry() failed: %s", ldap_err2string(ldap_result2error(ld, result, 0)));
#endif
		ldap_msgfree(result);
		return NULL;
	}

	if ((values = ldap_get_values(ld, e, s_cfg->home_attr)) == NULL) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_get_values(\"%s\") failed: %s", s_cfg->home_attr, ldap_err2string(ldap_result2error(ld, result, 0)));
#else
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_get_values(\"%s\") failed: %s", s_cfg->home_attr, ldap_err2string(ldap_result2error(ld, result, 0)));
#endif
		ldap_msgfree(result);
		return NULL;
	}

	homedir = AP_PSTRDUP(r->pool, values[0]);
#ifdef STANDARD20_MODULE_STUFF
	cache_set(s_cfg, username, homedir);
#endif /* STANDARD20_MODULE_STUFF */

	ldap_msgfree(result);
	ldap_value_free(values);
	return homedir;
}

static int
translate_ldap_userdir(request_rec *r)
{
	const ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(r->server->module_config, &ldap_userdir_module);
	const char *userdirs = s_cfg->userdir, *w, *dname, *homedir;
	char *name = r->uri;

	/*
	 * If the URI doesn't match our basic pattern, we've nothing to do with
	 * it.
	 */
	if ((! s_cfg->enabled) ||
	    (name[0] != '/') ||
	    (name[1] != '~'))
	{
		return DECLINED;
	}

	dname = name + 2;
	w = ap_getword(r->pool, &dname, '/');

	/*
	 * This 'dname' funny business involves backing it up to capture the '/'
	 * delimiting the "/~user" part from the rest of the URL, in case there
	 * was one (the case where there wasn't being just "GET /~user HTTP/1.0",
	 * for which we don't want to tack on a '/' onto the filename).
	 */
	if (dname[-1] == '/') {
		--dname;
	}

	/*
	 * If there's no username, it's not for us. Ignore . and .. as well.
	 */
	if (w[0] == '\0' || (w[1] == '.' && (w[2] == '\0' || (w[2] == '.' && w[3] == '\0')))) {
		return DECLINED;
	}

	if (! (homedir = get_ldap_homedir(s_cfg, r, w))) {
		return DECLINED;
	}

	while (*userdirs) {
		const char *userdir = ap_getword_conf(r->pool, &userdirs);
		char *filename;
#ifdef STANDARD20_MODULE_STUFF
		apr_finfo_t statbuf;
		apr_status_t rv;
		int is_absolute = ap_os_is_path_absolute(r->pool, userdir);
#else
		struct stat statbuf;
		int is_absolute = ap_os_is_path_absolute(userdir);
#endif
		char *x = NULL, *redirect;

		if (AP_STRCHR_C(userdir, '*')) {
			x = ap_getword(r->pool, &userdir, '*');
		}

		if (userdir[0] == '\0' || is_absolute) {
			if (x) {
				if (AP_STRSTR_C(x, "://") && !is_absolute)	{
					redirect = AP_PSTRCAT(r->pool, x, w, userdir, dname, NULL);
					AP_TABLE_SETN(r->headers_out, "Location", redirect);
					return HTTP_MOVED_TEMPORARILY;
				} else {
					filename = AP_PSTRCAT(r->pool, x, w, userdir, NULL);
				}
			} else {
				filename = AP_PSTRCAT(r->pool, userdir, "/", w, NULL);
			}
		} else if (x && AP_STRSTR_C(x, "://")) {
			redirect = AP_PSTRCAT(r->pool, x, w, userdir, dname, NULL);
			AP_TABLE_SETN(r->headers_out, "Location", redirect);
			return HTTP_MOVED_TEMPORARILY;
		} else {
			filename = AP_PSTRCAT(r->pool, homedir, "/", userdir, NULL);
		}

		/* Now see if it exists, or we're at the last entry. If we're
		 * at the last entry, then use the filename generated (if there
		 * is one) anyway, in the hope that some handler might handle
		 * it. This can be used, for example, to run a CGI script for
		 * the user.
		 */
#ifdef STANDARD20_MODULE_STUFF
		if (filename &&
		    (!*userdirs ||
		     ((rv = apr_stat(&statbuf, filename, APR_FINFO_MIN, r->pool)) == APR_SUCCESS ||
		      rv == APR_INCOMPLETE)))
#else
		if (filename && (!*userdirs || stat(filename, &statbuf) != -1))
#endif
		{
			r->filename = AP_PSTRCAT(r->pool, filename, dname, NULL);
			/* When statbuf contains info on r->filename, we can save
			 * a syscall by copying it to r->finfo.
			 */
			if (*userdirs && dname[0] == 0) {
				r->finfo = statbuf;
			}

			/* For use in the get_suexec_identity phase. */
			AP_TABLE_SETN(r->notes, "mod_ldap_userdir_user", w);

			return OK;
		}
	}

	return DECLINED;
}

#ifdef STANDARD20_MODULE_STUFF

#ifdef HAVE_UNIX_SUEXEC
static ap_unix_identity_t *get_suexec_id_doer(const request_rec *r)
{
	ap_unix_identity_t *ugid = NULL;
#if APR_HAS_USER
	const char *username = apr_table_get(r->notes, "mod_ldap_userdir_user");

	if (username == NULL) {
		return NULL;
	}

	if ((ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t *))) == NULL) {
		return NULL;
	}

	if (apr_get_userid(&ugid->uid, &ugid->gid, username, r->pool) != APR_SUCCESS) {
		return NULL;
	}

	ugid->userdir = 1;
#endif 
	return ugid;
}
#endif /* HAVE_UNIX_SUEXEC */

static void
register_hooks(AP_POOL *p)
{
	static const char *const aszPre[]  = {"mod_alias.c",       NULL};
	static const char *const aszSucc[] = {"mod_vhost_alias.c", NULL};
	ap_hook_translate_name(translate_ldap_userdir, aszPre, aszSucc, APR_HOOK_MIDDLE);

	ap_hook_post_config(init_ldap_userdir, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(child_init_ldap_userdir, NULL, NULL, APR_HOOK_MIDDLE);

#ifdef HAVE_UNIX_SUEXEC
	ap_hook_get_suexec_identity(get_suexec_id_doer, NULL, NULL, APR_HOOK_FIRST);
#endif
}

#endif /* STANDARD20_MODULE_STUFF */

static const command_rec ldap_userdir_cmds[] = {
#ifdef STANDARD20_MODULE_STUFF
	AP_INIT_RAW_ARGS("LDAPUserDir", set_ldap_user_dir, NULL, RSRC_CONF,
	                 "the public subdirectory in users' home directories"),
	AP_INIT_TAKE1("LDAPUserDirServer", set_server, NULL, RSRC_CONF,
	              "the LDAP directory server that will be used for LDAP UserDir queries"),
	AP_INIT_TAKE2("LDAPUserDirDNInfo", set_ldap_dninfo, NULL, RSRC_CONF,
	              "the DN and password that will be used to bind to the LDAP server when doing LDAP UserDir lookups"),
	AP_INIT_TAKE1("LDAPUserDirBaseDN", set_basedn, NULL, RSRC_CONF,
	              "the base DN that will be used when doing LDAP UserDir lookups"),
	AP_INIT_TAKE1("LDAPUserDirFilter", set_filter_template, NULL, RSRC_CONF,
	              "a template that will be used for the LDAP filter when doing LDAP UserDir lookups (%v is replaced with the username being resolved)"),
	AP_INIT_TAKE1("LDAPUserDirSearchScope", set_search_scope, NULL, RSRC_CONF,
	              "the LDAP search scope (\"onelevel\" or \"subtree\") that will be used when doing LDAP UserDir lookups"),
	AP_INIT_FLAG("LDAPUserDirUseTLS", set_use_tls, NULL, RSRC_CONF,
	             "whether to use an encrypted connection to the LDAP server"),
	AP_INIT_TAKE1("LDAPUserDirHomeAttribute", set_home_attr, NULL, RSRC_CONF,
	              "the name of the LDAP attribute containing the user's home directory"),
	AP_INIT_TAKE1("LDAPUserDirCacheTimeout", set_cache_timeout, NULL, RSRC_CONF,
	              "how long, in seconds, to store cached LDAP entries"),
#else /* STANDARD20_MODULE_STUFF */
	{"LDAPUserDir", set_ldap_user_dir, NULL, RSRC_CONF, RAW_ARGS,
	 "the public subdirectory in users' home directories"},
	{"LDAPUserDirServer", set_server, NULL, RSRC_CONF, TAKE1,
	 "the LDAP directory server that will be used for LDAP UserDir queries"},
	{"LDAPUserDirDNInfo", set_ldap_dninfo, NULL, RSRC_CONF, TAKE2,
	 "the DN and password that will be used to bind to the LDAP server when doing LDAP UserDir lookups"},
	{"LDAPUserDirBaseDN", set_basedn, NULL, RSRC_CONF, TAKE1,
	 "the base DN that will be used when doing LDAP UserDir lookups"},
	{"LDAPUserDirFilter", set_filter_template, NULL, RSRC_CONF, TAKE1,
	 "a template that will be used for the LDAP filter when doing LDAP UserDir lookups (%v is replaced with the username being resolved)"},
	{"LDAPUserDirSearchScope", set_search_scope, NULL, RSRC_CONF, TAKE1,
	 "the LDAP search scope (\"onelevel\" or \"subtree\") that will be used when doing LDAP UserDir lookups"},
	{"LDAPUserDirUseTLS", set_use_tls, NULL, RSRC_CONF, FLAG,
	 "whether to use an encrypted connection to the LDAP server"},
	{"LDAPUserDirHomeAttribute", set_home_attr, NULL, RSRC_CONF, TAKE1,
	 "the name of the LDAP attribute containing the user's home directory"},
	{"LDAPUserDirCacheTimeout", set_cache_timeout, NULL, RSRC_CONF, TAKE1,
	 "how long, in seconds, to store cached LDAP entries"},
#endif
	{NULL}
};

#ifdef STANDARD20_MODULE_STUFF
module AP_MODULE_DECLARE_DATA ldap_userdir_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                        /* dir config creater */
	NULL,                        /* dir merger --- default is to override */
	create_ldap_userdir_config,  /* server config */
	NULL,                        /* merge server config */
	ldap_userdir_cmds,           /* command table */
	register_hooks               /* register hooks */
#else
module MODULE_VAR_EXPORT ldap_userdir_module = {
	STANDARD_MODULE_STUFF,
	init_ldap_userdir,           /* initializer */
	NULL,                        /* dir config creater */
	NULL,                        /* dir merger --- default is to override */
	create_ldap_userdir_config,  /* server config */
	NULL,                        /* merge server config */
	ldap_userdir_cmds,           /* command table */
	NULL,                        /* handlers */
	translate_ldap_userdir,      /* filename translation */
	NULL,                        /* check_user_id */
	NULL,                        /* check auth */
	NULL,                        /* check access */
	NULL,                        /* type_checker */
	NULL,                        /* fixups */
	NULL,                        /* logger */
	NULL,                        /* header parser */
	child_init_ldap_userdir,     /* child_init */
	NULL,                        /* child_exit */
	NULL                         /* post read-request */
#endif
};
