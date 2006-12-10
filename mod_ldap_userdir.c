/*
 * mod_ldap_userdir - LDAP UserDir module for the Apache web server
 * Copyright 1999, 2000-3, John Morrissey <jwm@horde.net>
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
 * mod_ldap_userdir v1.1.4
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

#ifndef LDAP_HOMEDIR_ATTR
#define LDAP_HOMEDIR_ATTR "homeDirectory"
#endif

/* You should not have to change anything below. If you do, report it
 * as a bug.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#ifdef STANDARD20_MODULE_STUFF
# define APR_WANT_STRFUNC
# include "apr_want.h"
# include "apr_strings.h"
# define AP_POOL apr_pool_t
# define AP_PSTRDUP apr_pstrdup
# define AP_PSTRCAT apr_pstrcat
# define AP_PCALLOC apr_pcalloc
# define AP_STRSTR ap_strstr
# define AP_STRSTR_C ap_strstr_c
# define AP_STRCHR_C ap_strchr_c
# define AP_TABLE_SETN apr_table_setn
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

#ifndef DEFAULT_LDAP_USER_DIR
# define DEFAULT_LDAP_USER_DIR "public_html"
#endif

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
	int ldap_enabled;
#ifdef TLS
	int ldap_usetls;
#endif
	char *ldap_server, *ldap_dn, *ldap_dnpass,
	     *ldap_basedn, *ldap_filter_template;
	int ldap_searchscope;
} ldap_userdir_config;

static LDAP *ld = NULL;


static void *
create_ldap_userdir_config(AP_POOL *p, server_rec *s)
{
	ldap_userdir_config *newcfg = (ldap_userdir_config *) AP_PCALLOC(p, sizeof(ldap_userdir_config));

	newcfg->userdir = DEFAULT_LDAP_USER_DIR;
	newcfg->ldap_searchscope = LDAP_SCOPE_SUBTREE;
	return (void *)newcfg;
}

static const char *
set_ldap_user_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config (cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDir must be supplied with the public subdirectory in users' home directories (e.g., 'public_html').";
	}

	s_cfg->ldap_enabled = 1;
	s_cfg->userdir = AP_PSTRDUP(cmd->pool, arg);

	return NULL;
}

static const char *
set_ldap_server(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirServer must be supplied with the name of an LDAP server.";
	}

	s_cfg->ldap_server = AP_PSTRDUP(cmd->pool, arg);
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
	s_cfg->ldap_dnpass = (char *)pass;

	return NULL;
}

static const char *
set_ldap_basedn(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirBaseDN must be supplied with the LDAP base DN to use for UserDir lookups.";
	}

	s_cfg->ldap_basedn = AP_PSTRDUP(cmd->pool, arg);
	return NULL;
}

static const char *
set_ldap_filter_template(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirFilter must be supplied with a filter template to use for LDAP UserDir lookups.";
	}

	s_cfg->ldap_filter_template = AP_PSTRDUP(cmd->pool, arg);
	return NULL;
}

static const char *
set_ldap_searchscope(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDirSearchScope must be supplied with a search scope (\"onelevel\" or \"subtree\")";
	}

	if (strcasecmp(arg, "onelevel") == 0) {
		s_cfg->ldap_searchscope = LDAP_SCOPE_ONELEVEL;
		return NULL;
	} else if (strcasecmp(arg, "subtree") == 0) {
		s_cfg->ldap_searchscope = LDAP_SCOPE_SUBTREE;
		return NULL;
	}

	return "LDAPUserDirSearchScope must be either \"onelevel\" or \"subtree\".";
}

static const char *
set_ldap_usetls(cmd_parms *cmd, void *dummy, int arg)
{
#ifdef TLS
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);
	s_cfg->ldap_usetls = arg;
	return NULL;
#else
	return "You must recompile mod_ldap_userdir to enable TLS/SSL support!";
#endif /* TLS */
}

static void
init_ldap_userdir(server_rec *s, AP_POOL *p)
{
#ifdef STANDARD20_MODULE_STUFF
	ap_add_version_component(p, "mod_ldap_userdir/1.1.4");
#else
	ap_add_version_component("mod_ldap_userdir/1.1.4");
#endif
}

static int
connect_ldap_userdir(const ldap_userdir_config *s_cfg)
{
	int ret, sizelimit = 2;

	if ((ld = ldap_init(s_cfg->ldap_server, LDAP_PORT)) == NULL) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_init() to %s failed: %s", s_cfg->ldap_server, strerror(errno));
#else
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: ldap_init() to %s failed: %s", s_cfg->ldap_server, strerror(errno));
#endif
		return -1;
	}

#ifdef TLS
	if (s_cfg->ldap_usetls) {
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

	if ((ret = ldap_simple_bind_s(ld, s_cfg->ldap_dn, s_cfg->ldap_dnpass)) != LDAP_SUCCESS) {
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

static void child_init_ldap_userdir(server_rec *s, AP_POOL *p)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(s->module_config, &ldap_userdir_module);

	if (!s_cfg->ldap_enabled) {
		return;
	}

	(void) connect_ldap_userdir(s_cfg);
}

static void child_exit_ldap_userdir(server_rec *s, AP_POOL *p)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(s->module_config, &ldap_userdir_module);

	if (!s_cfg->ldap_enabled) {
		return;
	}

	/* We're just trying to be Good Neighbors in doing this; we don't
	   particularly care if it fails. Besides, it's not like there's
	   a whole lot we're going to do about it. :-) */
	if (ld != NULL) {
		ldap_unbind(ld);
	}
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

static const char *
get_ldap_homedir(const ldap_userdir_config *s_cfg, request_rec *r,
                 const char *username)
{
	char *filter, **values, *homedir,
		 *attrs[] = {LDAP_HOMEDIR_ATTR, NULL};
	int ret;
	LDAPMessage *result, *e;

	/* If we haven't even connected yet, try to connect. If we still can't
	   connect, give up. */
	if (ld == NULL) {
		if (connect_ldap_userdir(s_cfg) != 1) {
			return NULL;
		}
	}

	if (s_cfg->ldap_filter_template && *(s_cfg->ldap_filter_template)) {
		filter = generate_filter(r->pool, s_cfg->ldap_filter_template, username);
	} else {
		filter = generate_filter(r->pool, "(&(uid=%v)(objectClass=posixAccount))", username);
	}

	if ((ret = ldap_search_s(ld, s_cfg->ldap_basedn, s_cfg->ldap_searchscope, filter, attrs, 0, &result)) != LDAP_SUCCESS) {
		/* If the LDAP server went away, try to reconnect. If the reconnect
		   fails, give up and log accordingly. */
		if (ret == LDAP_SERVER_DOWN) {
#ifdef STANDARD20_MODULE_STUFF
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: LDAP server has gone away, attempting to reconnect. (ldap_search_s() failed: %s)", ldap_err2string(ret));
#else
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: LDAP server has gone away, attempting to reconnect. (ldap_search_s() failed: %s)", ldap_err2string(ret));
#endif
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

#ifdef STANDARD20_MODULE_STUFF
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: LDAP server went away, but a reconnect was successful. Resuming normal operations.");
#else
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: LDAP server went away, but a reconnect was successful. Resuming normal operations.");
#endif

			if ((ret = ldap_search_s(ld, s_cfg->ldap_basedn, s_cfg->ldap_searchscope, filter, attrs, 0, &result)) != LDAP_SUCCESS) {
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

	if ((e = ldap_first_entry(ld, result)) != NULL) {
		if ((values = ldap_get_values(ld, e, LDAP_HOMEDIR_ATTR)) == NULL) {
			/* We have to go through some theatrics here to get the
			 * errno; is accessing ld->ld_errno portable?
			 */
#ifdef STANDARD20_MODULE_STUFF
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_get_values(\"" LDAP_HOMEDIR_ATTR"\") failed: %s", ldap_err2string(ldap_result2error(ld, result, 0)));
#else
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_get_values(\"" LDAP_HOMEDIR_ATTR"\") failed: %s", ldap_err2string(ldap_result2error(ld, result, 0)));
#endif
			ldap_msgfree(result);
			return NULL;
		}
	} else {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_first_entry() failed: %s", ldap_err2string(ldap_result2error(ld, result, 0)));
#else
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_first_entry() failed: %s", ldap_err2string(ldap_result2error(ld, result, 0)));
#endif
		ldap_msgfree(result);
		return NULL;
	}

	homedir = AP_PSTRDUP(r->pool, values[0]);
	ldap_msgfree(result);
	ldap_value_free(values);
	return(homedir);
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
	if ((! s_cfg->ldap_enabled) ||
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
			return OK;
		}
	}

	return DECLINED;
}

#ifdef STANDARD20_MODULE_STUFF
static void
register_hooks(AP_POOL *p)
{
	static const char *const aszPre[]  = {"mod_alias.c",       NULL};
	static const char *const aszSucc[] = {"mod_vhost_alias.c", NULL};

	ap_hook_translate_name(translate_ldap_userdir, aszPre, aszSucc, APR_HOOK_MIDDLE);
}
#endif /* STANDARD20_MODULE_STUFF */

static const command_rec ldap_userdir_cmds[] = {
#ifdef STANDARD20_MODULE_STUFF
	AP_INIT_RAW_ARGS("LDAPUserDir", set_ldap_user_dir, NULL, RSRC_CONF,
	                 "the public subdirectory in users' home directories"),
	AP_INIT_TAKE1("LDAPUserDirServer", set_ldap_server, NULL, RSRC_CONF,
	              "the LDAP directory server that will be used for LDAP UserDir queries"),
	AP_INIT_TAKE2("LDAPUserDirDNInfo", set_ldap_dninfo, NULL, RSRC_CONF,
	              "the DN and password that will be used to bind to the LDAP server when doing LDAP UserDir lookups"),
	AP_INIT_TAKE1("LDAPUserDirBaseDN", set_ldap_basedn, NULL, RSRC_CONF,
	              "the base DN that will be used when doing LDAP UserDir lookups"),
	AP_INIT_TAKE1("LDAPUserDirFilter", set_ldap_filter_template, NULL, RSRC_CONF,
	              "a template that will be used for the LDAP filter when doing LDAP UserDir lookups (%v is replaced with the username being resolved)"),
	AP_INIT_TAKE1("LDAPUserDirSearchScope", set_ldap_searchscope, NULL, RSRC_CONF,
	              "the LDAP search scope (\"onelevel\" or \"subtree\") that will be used when doing LDAP UserDir lookups"),
	AP_INIT_FLAG("LDAPUserDirUseTLS", set_ldap_usetls, NULL, RSRC_CONF,
	             "whether to use an encrypted connection to the LDAP server"),
#else /* STANDARD20_MODULE_STUFF */
	{"LDAPUserDir", set_ldap_user_dir, NULL, RSRC_CONF, RAW_ARGS,
	 "the public subdirectory in users' home directories"},
	{"LDAPUserDirServer", set_ldap_server, NULL, RSRC_CONF, TAKE1,
	 "the LDAP directory server that will be used for LDAP UserDir queries"},
	{"LDAPUserDirDNInfo", set_ldap_dninfo, NULL, RSRC_CONF, TAKE2,
	 "the DN and password that will be used to bind to the LDAP server when doing LDAP UserDir lookups"},
	{"LDAPUserDirBaseDN", set_ldap_basedn, NULL, RSRC_CONF, TAKE1,
	 "the base DN that will be used when doing LDAP UserDir lookups"},
	{"LDAPUserDirFilter", set_ldap_filter_template, NULL, RSRC_CONF, TAKE1,
	 "a template that will be used for the LDAP filter when doing LDAP UserDir lookups (%v is replaced with the username being resolved)"},
	{"LDAPUserDirSearchScope", set_ldap_searchscope, NULL, RSRC_CONF, TAKE1,
	 "the LDAP search scope (\"onelevel\" or \"subtree\") that will be used when doing LDAP UserDir lookups"},
	{"LDAPUserDirUseTLS", set_ldap_usetls, NULL, RSRC_CONF, FLAG,
	 "whether to use an encrypted connection to the LDAP server"},
#endif
	{NULL}
};

#ifdef STANDARD20_MODULE_STUFF
module AP_MODULE_DECLARE_DATA ldap_userdir_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                         /* dir config creater */
	NULL,                         /* dir merger --- default is to override */
	create_ldap_userdir_config,   /* server config */
	NULL,                         /* merge server config */
	ldap_userdir_cmds,            /* command table */
	register_hooks                /* register hooks */
#else
module MODULE_VAR_EXPORT ldap_userdir_module = {
	STANDARD_MODULE_STUFF,
	init_ldap_userdir,			/* initializer */
	NULL,						/* dir config creater */
	NULL,						/* dir merger --- default is to override */
	create_ldap_userdir_config, /* server config */
	NULL,						/* merge server config */
	ldap_userdir_cmds,			/* command table */
	NULL,						/* handlers */
	translate_ldap_userdir,		/* filename translation */
	NULL,						/* check_user_id */
	NULL,						/* check auth */
	NULL,						/* check access */
	NULL,						/* type_checker */
	NULL,						/* fixups */
	NULL,						/* logger */
	NULL,						/* header parser */
	child_init_ldap_userdir,	/* child_init */
	child_exit_ldap_userdir,	/* child_exit */
	NULL						/* post read-request */
#endif
};
