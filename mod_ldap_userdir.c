/*
 * mod_ldap_userdir - LDAP UserDir module for the Apache web server
 * Copyright 1999, 2000-6, John Morrissey <jwm@horde.net>
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
 * mod_ldap_userdir v1.1.11
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
 *       NOTE:    these ^ ^ spaces are here to allow this to work in a
 *             C-style comment; they should not be included in your
 *             configuration.
 *
 * You can use multiple entries, to specify alternate user
 * directories (a la DirectoryIndex). For example:
 *
 * LDAPUserDir public_html public_www
 * LDAPUserDir public_html /usr/web http://www.xyz.com/users
 */


#include "config.h"

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
	char *server, *ldap_dn, *dn_pass,
	     *basedn, *filter_template,
	     *home_attr, *username_attr;
	int port, search_scope, cache_timeout, protocol_version;
#ifdef TLS
	int use_tls;
#endif

	LDAP *ld;

	unsigned int got_url;

#ifdef STANDARD20_MODULE_STUFF
	apr_hash_t *homedirHt;
#endif /* STANDARD20_MODULE_STUFF */
} ldap_userdir_config;

#ifdef STANDARD20_MODULE_STUFF
struct hash_entry {
	time_t inserted_at;
	char *homedir;
	char *posix_username;
};
#endif /* STANDARD20_MODULE_STUFF */

static void *
create_ldap_userdir_config(AP_POOL *p, server_rec *s)
{
	ldap_userdir_config *newcfg = (ldap_userdir_config *) AP_PCALLOC(p, sizeof(ldap_userdir_config));

	newcfg->port = -1;
	newcfg->search_scope = -1;
	newcfg->cache_timeout = -1;
	newcfg->protocol_version = -1;
#ifdef TLS
	newcfg->use_tls = -1;
#endif /* TLS */

	newcfg->got_url = 0;

#ifdef STANDARD20_MODULE_STUFF
	newcfg->homedirHt = apr_hash_make(p);
#endif /* STANDARD20_MODULE_STUFF */
	return (void *)newcfg;
}

static void *
merge_ldap_userdir_config(AP_POOL *p, void *server1_conf, void *server2_conf)
{
	ldap_userdir_config *s_cfg1 = (ldap_userdir_config *) server1_conf,
	                    *s_cfg2 = (ldap_userdir_config *) server2_conf;

    ldap_userdir_config *merged_cfg =
    	(ldap_userdir_config *) AP_PCALLOC(p, sizeof(ldap_userdir_config));
	memcpy(merged_cfg, s_cfg2, sizeof(ldap_userdir_config));

	if (!merged_cfg->userdir) {
		merged_cfg->userdir = AP_PSTRDUP(p, s_cfg1->userdir);
	}
	if (!merged_cfg->server) {
		merged_cfg->server = AP_PSTRDUP(p, s_cfg1->server);
	}
	if (!merged_cfg->ldap_dn) {
		merged_cfg->ldap_dn = AP_PSTRDUP(p, s_cfg1->ldap_dn);
	}
	if (!merged_cfg->dn_pass) {
		merged_cfg->dn_pass = AP_PSTRDUP(p, s_cfg1->dn_pass);
	}
	if (!merged_cfg->basedn) {
		merged_cfg->basedn = AP_PSTRDUP(p, s_cfg1->basedn);
	}
	if (!merged_cfg->filter_template) {
		merged_cfg->filter_template = AP_PSTRDUP(p, s_cfg1->filter_template);
	}
	if (!merged_cfg->home_attr) {
		merged_cfg->home_attr = AP_PSTRDUP(p, s_cfg1->home_attr);
	}
	if (!merged_cfg->username_attr) {
		merged_cfg->username_attr = AP_PSTRDUP(p, s_cfg1->username_attr);
	}
	if (merged_cfg->port == -1) {
		merged_cfg->port = s_cfg1->port;
	}
	if (merged_cfg->search_scope == -1) {
		merged_cfg->search_scope = s_cfg1->search_scope;
	}
	if (merged_cfg->cache_timeout == -1) {
		merged_cfg->cache_timeout = s_cfg1->cache_timeout;
	}
	if (merged_cfg->protocol_version == -1) {
		merged_cfg->protocol_version = s_cfg1->protocol_version;
	}
#ifdef TLS
	if (merged_cfg->use_tls == -1) {
		merged_cfg->use_tls = s_cfg1->use_tls;
	}
#endif /* TLS */

    return (void *) merged_cfg;
}

static const char *
set_ldap_user_dir(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(arg) == 0) {
		return "LDAPUserDir must be supplied with the public subdirectory in users' home directories (e.g., 'public_html').";
	}

	s_cfg->userdir = AP_PSTRDUP(cmd->pool, arg);
	return NULL;
}

static const char *
set_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);
	LDAPURLDesc *url;

	if (s_cfg->server || s_cfg->basedn || s_cfg->filter_template ||
	    s_cfg->search_scope != -1)
	{
		return "LDAPUserDirServerURL can't be combined with LDAPUserDirServer, LDAPUserDirBaseDN, LDAPUserDirFilter, or LDAPUserDirSearchScope.";
	}
#ifdef TLS
	if (s_cfg->use_tls != -1) {
		return "LDAPUserDirServerURL can't be combined with LDAPUserDirUseTLS.";
	}
#endif /* TLS */
	s_cfg->got_url = 1;

	if (ldap_url_parse(arg, &url) != LDAP_SUCCESS) {
		return "LDAPUserDirServerURL must be supplied with a valid LDAP URL.";
	}

#ifdef HAVE_LDAPURLDESC_LUD_SCHEME
# define SCHEME_IS(scheme) \
	((strlen(url->lud_scheme) == strlen(scheme) - 1) && \
	 (strncasecmp(url->lud_scheme, scheme, strlen(scheme) - 1) == 0))
#else /* HAVE_LDAPURLDESC_LUD_SCHEME */
# define SCHEME_IS(scheme) (strncasecmp(arg, scheme, strlen(scheme)) == 0)
#endif /* HAVE_LDAPURLDESC_LUD_SCHEME */

#ifdef TLS
	if (SCHEME_IS("ldap:")) {
		s_cfg->use_tls = 0;
	} else if (SCHEME_IS("ldaps:")) {
		s_cfg->use_tls = 1;
	} else {
		return "Invalid scheme specified by LDAPUserDirServerURL. Valid schemes are 'ldap' or 'ldaps'.";
	}
#else /* TLS */
	if (!SCHEME_IS("ldap:")) {
		return "Invalid scheme specified by LDAPUserDirServerURL. Valid schemes are 'ldap'.";
	}
#endif /* TLS */

	if (url->lud_host != NULL) {
		s_cfg->server = AP_PSTRDUP(cmd->pool, url->lud_host);
	}
	if (url->lud_port != 0) {
		s_cfg->port = url->lud_port;
	}
	if (url->lud_dn != NULL) {
		s_cfg->basedn = AP_PSTRDUP(cmd->pool, url->lud_dn);
	}
	if (url->lud_filter != NULL) {
		s_cfg->filter_template = AP_PSTRDUP(cmd->pool, url->lud_filter);
	}
	if (url->lud_scope != 0) {
		s_cfg->search_scope = url->lud_scope;
	}

	ldap_free_urldesc(url);
	return NULL;
}

static const char *
set_server(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (s_cfg->got_url) {
		return "LDAPUserDirServer can't be combined with LDAPUserDirServerURL.";
	}

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

	if (s_cfg->got_url) {
		return "LDAPUserDirBaseDN can't be combined with LDAPUserDirServerURL.";
	}

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

	if (s_cfg->got_url) {
		return "LDAPUserDirFilter can't be combined with LDAPUserDirServerURL.";
	}

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

	if (s_cfg->got_url) {
		return "LDAPUserDirSearchScope can't be combined with LDAPUserDirServerURL.";
	}

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

	if (s_cfg->got_url) {
		return "LDAPUserDirUseTLS can't be combined with LDAPUserDirServerURL.";
	}
	if (s_cfg->protocol_version < 3 && s_cfg->protocol_version != -1) {
		return "LDAPProtocolVersion must be set to version 3 to use the LDAPUserDirUseTLS directive.";
	}

	s_cfg->use_tls = arg;
	return NULL;
#else
	return "mod_ldap_userdir was not built with LDAP TLS/SSL support.";
#endif /* TLS */
}

static const char *
set_attr_name(cmd_parms *cmd, void *dummy,
              const char *our_attr, const char *their_attr)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (strlen(their_attr) == 0) {
		return "LDAPAttributeName must be supplied with a non-empty attribute name for its second argument, such as \"homeDirectory\"";
	}

	if (strcasecmp(our_attr, "homeDirectory") == 0) {
		s_cfg->home_attr = AP_PSTRDUP(cmd->pool, their_attr);
	} else if (strcasecmp(our_attr, "uid") == 0) {
		s_cfg->username_attr = AP_PSTRDUP(cmd->pool, their_attr);
	} else {
		return "LDAPAttributeName accepts only \"homeDirectory\" or \"uid\" for its first argument.";
	}

	return NULL;
}

static const char *
set_cache_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
	char *invalid_char = NULL;
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	s_cfg->cache_timeout = strtol(arg, &invalid_char, 10);
	if (arg[0] == '\0' || *invalid_char != '\0') {
		return "LDAPUserDirCacheTimeout must be supplied with a numeric cache timeout.";
	}
	return NULL;
}

static const char *
set_ldap_protocol_version(cmd_parms *cmd, void *dummy, const char *arg)
{
	char *invalid_char = NULL;
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	s_cfg->protocol_version = strtol(arg, &invalid_char, 10);
	if (arg[0] == '\0' || *invalid_char != '\0' || (s_cfg->protocol_version != 2 && s_cfg->protocol_version != 3)) {
		return "LDAPProtocolVersion must be set as version 2 or version 3.";
	}
#ifdef TLS
	if (s_cfg->protocol_version < 3 && s_cfg->use_tls != -1) {
		return "LDAPProtocolVersion must be set to version 3 to use the LDAPUserDirUseTLS directive.";
	}
#endif /* TLS */
	return NULL;
}

static void
apply_config_defaults(ldap_userdir_config *cfg)
{
	if (!cfg->home_attr) {
		cfg->home_attr = "homeDirectory";
	}
	if (!cfg->username_attr) {
		cfg->username_attr = "uid";
	}
	if (cfg->port == -1) {
		cfg->port = LDAP_PORT;
	}
	if (cfg->search_scope == -1) {
		cfg->search_scope = LDAP_SCOPE_SUBTREE;
	}
	if (cfg->cache_timeout == -1) {
		cfg->cache_timeout = 300;
	}
	if (cfg->protocol_version == -1) {
		cfg->protocol_version = 3;
	}
#ifdef TLS
	if (cfg->use_tls == -1) {
		cfg->use_tls = 0;
	}
#endif /* TLS */
}

#ifdef STANDARD20_MODULE_STUFF
static int
init_ldap_userdir(AP_POOL *pconf, AP_POOL *plog,
                  AP_POOL *ptemp, server_rec *s)
{
	for (; s; s = s->next) {
		ldap_userdir_config *s_cfg =
			(ldap_userdir_config *) ap_get_module_config(s->module_config, &ldap_userdir_module);
		apply_config_defaults(s_cfg);
	}

	ap_add_version_component(pconf, "mod_ldap_userdir/1.1.11");
	return OK;
}
#else /* STANDARD20_MODULE_STUFF */
static void
init_ldap_userdir(server_rec *s, AP_POOL *p)
{
	for (; s; s = s->next) {
		ldap_userdir_config *s_cfg =
 			(ldap_userdir_config *) ap_get_module_config(s->module_config, &ldap_userdir_module);
		apply_config_defaults(s_cfg);
	}

	ap_add_version_component("mod_ldap_userdir/1.1.11");
}
#endif /* STANDARD20_MODULE_STUFF */

static int
connect_ldap_userdir(ldap_userdir_config *s_cfg)
{
	int ret, sizelimit = 2, version;

	if ((s_cfg->ld = (LDAP *) ldap_init(s_cfg->server, s_cfg->port)) == NULL) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_init() to %s failed: %s", s_cfg->server, strerror(errno));
#else
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: ldap_init() to %s failed: %s", s_cfg->server, strerror(errno));
#endif
		return -1;
	}

	switch (s_cfg->protocol_version) {
	case 2:
		version = LDAP_VERSION2;
		break;
	case 3:
	default:
		version = LDAP_VERSION3;
		break;
	}

	if ((ret = ldap_set_option(s_cfg->ld, LDAP_OPT_PROTOCOL_VERSION, &version)) != LDAP_OPT_SUCCESS) {
#ifdef STANDARD20_MODULE_STUFF
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: Setting LDAP version option failed: %s", ldap_err2string(ret));
#else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: Setting LDAP version option failed: %s", ldap_err2string(ret));
#endif
			ldap_unbind(s_cfg->ld);
			s_cfg->ld = NULL;
			return -1;
		}

#ifdef TLS
	if (s_cfg->use_tls) {
		if ((ret = ldap_start_tls_s(s_cfg->ld, NULL, NULL)) != LDAP_SUCCESS) {
#ifdef STANDARD20_MODULE_STUFF
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: Starting TLS failed: %s", ldap_err2string(ret));
#else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: Starting TLS failed: %s", ldap_err2string(ret));
#endif
			ldap_unbind(s_cfg->ld);
			s_cfg->ld = NULL;
			return -1;
		}
	}
#endif /* TLS */

	if ((ret = ldap_simple_bind_s(s_cfg->ld, s_cfg->ldap_dn, s_cfg->dn_pass)) != LDAP_SUCCESS) {
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
	if ((ret = ldap_set_option(s_cfg->ld, LDAP_OPT_SIZELIMIT, (void *)&sizelimit)) != LDAP_OPT_SUCCESS)
#ifdef STANDARD20_MODULE_STUFF
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_set_option() unable to set query size limit to 2 entries: %s", ldap_err2string(ret));
#else /* STANDARD20_MODULE_STUFF */
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, NULL, "mod_ldap_userdir: ldap_set_option() unable to set query size limit to 2 entries: %s", ldap_err2string(ret));
#endif /* STANDARD20_MODULE_STUFF */
#else /* LDAP_OPT_SIZELIMIT */
	s_cfg->ld->ld_sizelimit = sizelimit;
#endif /* LDAP_OPT_SIZELIMIT */

	return 1;
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
	pos = template;
	while ((pos = AP_STRSTR(pos + 2, "%u")) != NULL) {
		++num_escapes;
	}

	/* -2 for the %u/%v, +1 for the NULL */
	filter = AP_PCALLOC(p, strlen(template) - (num_escapes * 2) + (num_escapes * strlen(entity)) + 1);

	while (template[i] != '\0') {
		if (template[i] == '%' &&
		    (template[i + 1] == 'u' || template[i + 1] == 'v'))
		{
			strcat(filter, entity);
			j += strlen(entity);
			i += 2;
		} else {
			filter[j++] = template[i++];
		}
	}

	return filter;
}


static struct hash_entry *
cache_fetch(const ldap_userdir_config *s_cfg, const char *username)
{
#ifndef STANDARD20_MODULE_STUFF
	return NULL;
#else /* STANDARD20_MODULE_STUFF */
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
		return cached;
	}

	free(cached->homedir);
	free(cached->posix_username);
	free(cached);
	apr_hash_set(s_cfg->homedirHt, username, APR_HASH_KEY_STRING, NULL);
	return NULL;
#endif /* !STANDARD20_MODULE_STUFF */
}

static struct hash_entry *
cache_set(const ldap_userdir_config *s_cfg,
          const char *username, const char *homedir, const char *posix_username)
{
	struct hash_entry *cached;

	/* A cache timeout of 0 disables caching. */
	if (s_cfg->cache_timeout == 0) {
		return NULL;
	}

	cached = (struct hash_entry *) malloc(sizeof(struct hash_entry));
	if (cached == NULL) {
		return NULL;
	}

	cached->homedir = strdup(homedir);
	if (cached->homedir == NULL) {
		free(cached);
		return NULL;
	}

	cached->posix_username = strdup(posix_username);
	if (cached->posix_username == NULL) {
		free(cached->homedir);
		free(cached);
		return NULL;
	}

	cached->inserted_at = time(NULL);

#ifdef STANDARD20_MODULE_STUFF
	apr_hash_set(s_cfg->homedirHt, username, APR_HASH_KEY_STRING, cached);
#endif /* STANDARD20_MODULE_STUFF */
	return cached;
}


static struct hash_entry *
get_ldap_homedir(ldap_userdir_config *s_cfg, request_rec *r,
                 const char *username)
{
	char *filter, **values, *homedir, *posix_username,
	     *attrs[] = {s_cfg->home_attr, s_cfg->username_attr, NULL};
	int ret;
	LDAPMessage *result, *e;
	struct hash_entry *cached;

#ifdef STANDARD20_MODULE_STUFF
	cached = cache_fetch(s_cfg, username);
	if (cached != NULL) {
		return cached;
	}
#endif /* STANDARD20_MODULE_STUFF */

	/* If we haven't even connected yet, try to connect. If we still can't
	   connect, give up. */
	if (s_cfg->ld == NULL) {
		if (connect_ldap_userdir(s_cfg) != 1) {
			return NULL;
		}
	}

	if (s_cfg->filter_template && *(s_cfg->filter_template)) {
		filter = generate_filter(r->pool, s_cfg->filter_template, username);
	} else {
		filter = generate_filter(r->pool, "(&(uid=%u)(objectClass=posixAccount))", username);
	}

	if ((ret = ldap_search_s(s_cfg->ld, s_cfg->basedn, s_cfg->search_scope, filter, attrs, 0, &result)) != LDAP_SUCCESS) {
		/* If the LDAP server went away, try to reconnect. If the reconnect
		 * fails, give up and log accordingly.
		 */
		if (ret == LDAP_SERVER_DOWN) {
			ldap_unbind(s_cfg->ld);

			if (connect_ldap_userdir(s_cfg) != 1) {
#ifdef STANDARD20_MODULE_STUFF
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: LDAP server went away, couldn't reconnect. Declining request.");
#else
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: LDAP server went away, couldn't reconnect. Declining request.");
#endif
				s_cfg->ld = NULL;
				return NULL;
			}

			if ((ret = ldap_search_s(s_cfg->ld, s_cfg->basedn, s_cfg->search_scope, filter, attrs, 0, &result)) != LDAP_SUCCESS) {
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

	if ((ret = ldap_count_entries(s_cfg->ld, result)) > 1) {
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

	if ((e = ldap_first_entry(s_cfg->ld, result)) == NULL) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_first_entry() failed: %s", ldap_err2string(ldap_result2error(s_cfg->ld, result, 0)));
#else
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_first_entry() failed: %s", ldap_err2string(ldap_result2error(s_cfg->ld, result, 0)));
#endif
		ldap_msgfree(result);
		return NULL;
	}

	if ((values = (char **) ldap_get_values(s_cfg->ld, e, s_cfg->home_attr)) == NULL) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_get_values(\"%s\") failed: %s", s_cfg->home_attr, ldap_err2string(ldap_result2error(s_cfg->ld, result, 0)));
#else
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_get_values(\"%s\") failed: %s", s_cfg->home_attr, ldap_err2string(ldap_result2error(s_cfg->ld, result, 0)));
#endif
		ldap_msgfree(result);
		return NULL;
	}
	homedir = AP_PSTRDUP(r->pool, values[0]);

	if ((values = (char **) ldap_get_values(s_cfg->ld, e, s_cfg->username_attr)) == NULL) {
#ifdef STANDARD20_MODULE_STUFF
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_get_values(\"%s\") failed: %s", s_cfg->username_attr, ldap_err2string(ldap_result2error(s_cfg->ld, result, 0)));
#else
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, r, "mod_ldap_userdir: ldap_get_values(\"%s\") failed: %s", s_cfg->username_attrr, ldap_err2string(ldap_result2error(s_cfg->ld, result, 0)));
#endif
		ldap_msgfree(result);
		return NULL;
	}
	posix_username = AP_PSTRDUP(r->pool, values[0]);

	ldap_msgfree(result);
	ldap_value_free(values);

	return cache_set(s_cfg, username, homedir, posix_username);
}

static int
translate_ldap_userdir(request_rec *r)
{
	const char *w, *dname;
	char *name = r->uri;
	const ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(r->server->module_config, &ldap_userdir_module);
	const char *userdirs = s_cfg->userdir;
	struct hash_entry *user_info;

	/*
	 * If the URI doesn't match our basic pattern, we've nothing to do with
	 * it.
	 */
	if ((s_cfg->userdir == NULL) ||
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

	user_info = get_ldap_homedir((ldap_userdir_config *)s_cfg, r, w);
	if (user_info == NULL) {
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
			filename = AP_PSTRCAT(r->pool, user_info->homedir, "/", userdir, NULL);
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
			AP_TABLE_SETN(r->notes, "mod_ldap_userdir_user", user_info->posix_username);

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

	if (apr_uid_get(&ugid->uid, &ugid->gid, username, r->pool) != APR_SUCCESS) {
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
	AP_INIT_TAKE1("LDAPUserDirServerURL", set_url, NULL, RSRC_CONF,
	              "the LDAP URL that will be used for LDAP UserDir queries"),
	AP_INIT_TAKE2("LDAPUserDirDNInfo", set_ldap_dninfo, NULL, RSRC_CONF,
	              "the DN and password that will be used to bind to the LDAP server when doing LDAP UserDir lookups"),
	AP_INIT_TAKE1("LDAPUserDirBaseDN", set_basedn, NULL, RSRC_CONF,
	              "the base DN that will be used when doing LDAP UserDir lookups"),
	AP_INIT_TAKE1("LDAPUserDirFilter", set_filter_template, NULL, RSRC_CONF,
	              "a template that will be used for the LDAP filter when doing LDAP UserDir lookups (%u and %v are replaced with the username being resolved)"),
	AP_INIT_TAKE1("LDAPUserDirSearchScope", set_search_scope, NULL, RSRC_CONF,
	              "the LDAP search scope (\"onelevel\" or \"subtree\") that will be used when doing LDAP UserDir lookups"),
	AP_INIT_FLAG("LDAPUserDirUseTLS", set_use_tls, NULL, RSRC_CONF,
	             "whether to use an encrypted connection to the LDAP server"),
	AP_INIT_TAKE2("LDAPAttributeName", set_attr_name, NULL, RSRC_CONF,
	             "alternate LDAP attribute names to use"),
	AP_INIT_TAKE1("LDAPUserDirCacheTimeout", set_cache_timeout, NULL, RSRC_CONF,
	              "how long, in seconds, to store cached LDAP entries"),
	AP_INIT_TAKE1("LDAPProtocolVersion", set_ldap_protocol_version, NULL, RSRC_CONF,
	              "the LDAP protocol version to use"),
#else /* STANDARD20_MODULE_STUFF */
	{"LDAPUserDir", set_ldap_user_dir, NULL, RSRC_CONF, RAW_ARGS,
	 "the public subdirectory in users' home directories"},
	{"LDAPUserDirServer", set_server, NULL, RSRC_CONF, TAKE1,
	 "the LDAP directory server that will be used for LDAP UserDir queries"},
	{"LDAPUserDirServerURL", set_url, NULL, RSRC_CONF, TAKE1,
	 "the LDAP URL that will be used for LDAP UserDir queries"},
	{"LDAPUserDirDNInfo", set_ldap_dninfo, NULL, RSRC_CONF, TAKE2,
	 "the DN and password that will be used to bind to the LDAP server when doing LDAP UserDir lookups"},
	{"LDAPUserDirBaseDN", set_basedn, NULL, RSRC_CONF, TAKE1,
	 "the base DN that will be used when doing LDAP UserDir lookups"},
	{"LDAPUserDirFilter", set_filter_template, NULL, RSRC_CONF, TAKE1,
	 "a template that will be used for the LDAP filter when doing LDAP UserDir lookups (%u and %v are replaced with the username being resolved)"},
	{"LDAPUserDirSearchScope", set_search_scope, NULL, RSRC_CONF, TAKE1,
	 "the LDAP search scope (\"onelevel\" or \"subtree\") that will be used when doing LDAP UserDir lookups"},
	{"LDAPUserDirUseTLS", set_use_tls, NULL, RSRC_CONF, FLAG,
	 "whether to use an encrypted connection to the LDAP server"},
	{"LDAPAttributeName", set_attr_name, NULL, RSRC_CONF, TAKE2,
	 "alternate LDAP attribute names to use"},
	{"LDAPUserDirCacheTimeout", set_cache_timeout, NULL, RSRC_CONF, TAKE1,
	 "how long, in seconds, to store cached LDAP entries"},
	{"LDAPProtocolVersion", set_ldap_protocol_version, NULL, RSRC_CONF, TAKE1,
	 "the LDAP protocol version to use"},
#endif
	{NULL}
};

#ifdef STANDARD20_MODULE_STUFF
module AP_MODULE_DECLARE_DATA ldap_userdir_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                        /* dir config creater */
	NULL,                        /* dir merger --- default is to override */
	create_ldap_userdir_config,  /* server config */
	merge_ldap_userdir_config,   /* merge server config */
	ldap_userdir_cmds,           /* command table */
	register_hooks               /* register hooks */
#else
module MODULE_VAR_EXPORT ldap_userdir_module = {
	STANDARD_MODULE_STUFF,
	init_ldap_userdir,           /* initializer */
	NULL,                        /* dir config creater */
	NULL,                        /* dir merger --- default is to override */
	create_ldap_userdir_config,  /* server config */
	merge_ldap_userdir_config,   /* merge server config */
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
	NULL,                        /* child_init */
	NULL,                        /* child_exit */
	NULL                         /* post read-request */
#endif
};
