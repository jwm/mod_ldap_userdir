/*
 * mod_ldap_userdir - LDAP UserDir module for the Apache web server
 * Copyright 1999 - 2010, John Morrissey <jwm@horde.net>
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
 * mod_ldap_userdir v1.1.19
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

/* httpd.h, please don't complain about my strtoul() usage.
 * sunos4 doesn't matter much to me.
 */
#undef strtoul
#define APR_WANT_STRFUNC
#include "apr_hash.h"
#include "apr_strings.h"
#include "apr_want.h"
#include <time.h>
#if !defined(WIN32) && !defined(OS2) && !defined(BEOS) && !defined(NETWARE)
# define HAVE_UNIX_SUEXEC
# include "unixd.h"  /* Contains the suexec_identity hook used on Unix */
#endif

#include <lber.h>
#include <ldap.h>

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_VENDOR_VERSION >= 192)
# define HAS_LDAP_UNBIND_EXT_S
#endif

#if defined(LDAP_API_FEATURE_X_OPENLDAP) && (LDAP_VENDOR_VERSION >= 19905)
# define HAS_LDAP_INITIALIZE
#endif

#if LDAP_API_VERSION >= 2000
# define LDAP_VALUE(values, i) (values[i]->bv_val)
# define LDAP_VALUE_FREE(values) (ldap_value_free_len(values))
#else
# define LDAP_VALUE(values, i) (values[i])
# define LDAP_VALUE_FREE(values) (ldap_value_free(values))
#endif

#ifdef HAS_LDAP_UNBIND_EXT_S
# define LDAP_UNBIND(ld) (ldap_unbind_ext_s(ld, NULL, NULL))
#else
# define LDAP_UNBIND(ld) (ldap_unbind_s(ld, NULL, NULL))
#endif

/* Thanks, Sun. */
#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

module AP_MODULE_DECLARE_DATA ldap_userdir_module;

typedef struct ldap_userdir_config {
	char *userdir;

	apr_array_header_t *userdirs;

	apr_array_header_t *servers;
	unsigned int cur_server_index;

#if LDAP_API_VERSION >= 2000
	char *url;
#else /* LDAP_API_VERSION >= 2000 */
	char *server;
	int port;
#endif /* LDAP_API_VERSION >= 2000 */

	char *ldap_dn, *dn_pass,
	     *basedn, *filter_template,
	     *home_attr, *username_attr, *uidNumber_attr, *gidNumber_attr;
	int search_scope, protocol_version;

	int cache_timeout;

#ifdef TLS
	int use_tls;
#endif

	LDAP *ld;

	unsigned int got_url;

	apr_hash_t *homedirHt;
} ldap_userdir_config;

struct hash_entry {
	time_t inserted_at;
	char *homedir;
	char *posix_username;
	char *uid;
	char *gid;
};

static void *
create_ldap_userdir_config(apr_pool_t *p, server_rec *s)
{
	ldap_userdir_config *newcfg = (ldap_userdir_config *) apr_pcalloc(p, sizeof(ldap_userdir_config));

	newcfg->userdirs = apr_array_make(p, 1, sizeof(char *));

	newcfg->servers = apr_array_make(p, 2, sizeof(char *));

#if LDAP_API_VERSION < 2000
	newcfg->port = -1;
#endif /* LDAP_API_VERSION < 2000 */

	newcfg->search_scope = -1;
	newcfg->protocol_version = -1;

#ifdef TLS
	newcfg->use_tls = -1;
#endif /* TLS */

	newcfg->cache_timeout = -1;
	newcfg->homedirHt = apr_hash_make(p);

	return (void *)newcfg;
}

static void *
merge_ldap_userdir_config(apr_pool_t *p, void *server1_conf, void *server2_conf)
{
	ldap_userdir_config *s_cfg1 = (ldap_userdir_config *) server1_conf,
	                    *s_cfg2 = (ldap_userdir_config *) server2_conf;

	ldap_userdir_config *merged_cfg =
		(ldap_userdir_config *) apr_pcalloc(p, sizeof(ldap_userdir_config));
	memcpy(merged_cfg, s_cfg2, sizeof(ldap_userdir_config));

	if (!merged_cfg->userdirs) {
		merged_cfg->userdirs = apr_array_copy_hdr(p, s_cfg1->userdirs);
	}

	if (!merged_cfg->servers) {
		merged_cfg->servers = apr_array_copy_hdr(p, s_cfg1->servers);
	}

#if LDAP_API_VERSION >= 2000
	if (!merged_cfg->url) {
		merged_cfg->url = apr_pstrdup(p, s_cfg1->url);
	}
#else /* LDAP_API_VERSION >= 2000 */
	if (!merged_cfg->server) {
		merged_cfg->server = apr_pstrdup(p, s_cfg1->server);
	}
	if (merged_cfg->port == -1) {
		merged_cfg->port = s_cfg1->port;
	}
#endif /* LDAP_API_VERSION >= 2000 */

	if (!merged_cfg->ldap_dn) {
		merged_cfg->ldap_dn = apr_pstrdup(p, s_cfg1->ldap_dn);
	}
	if (!merged_cfg->dn_pass) {
		merged_cfg->dn_pass = apr_pstrdup(p, s_cfg1->dn_pass);
	}
	if (!merged_cfg->basedn) {
		merged_cfg->basedn = apr_pstrdup(p, s_cfg1->basedn);
	}
	if (!merged_cfg->filter_template) {
		merged_cfg->filter_template = apr_pstrdup(p, s_cfg1->filter_template);
	}
	if (!merged_cfg->home_attr) {
		merged_cfg->home_attr = apr_pstrdup(p, s_cfg1->home_attr);
	}
	if (!merged_cfg->username_attr) {
		merged_cfg->username_attr = apr_pstrdup(p, s_cfg1->username_attr);
	}
	if (!merged_cfg->uidNumber_attr) {
		merged_cfg->uidNumber_attr = apr_pstrdup(p, s_cfg1->uidNumber_attr);
	}
	if (!merged_cfg->gidNumber_attr) {
		merged_cfg->gidNumber_attr = apr_pstrdup(p, s_cfg1->gidNumber_attr);
	}

	if (merged_cfg->search_scope == -1) {
		merged_cfg->search_scope = s_cfg1->search_scope;
	}
	if (merged_cfg->protocol_version == -1) {
		merged_cfg->protocol_version = s_cfg1->protocol_version;
	}

	if (merged_cfg->cache_timeout == -1) {
		merged_cfg->cache_timeout = s_cfg1->cache_timeout;
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
		return "LDAPUserDir must be supplied with the public subdirectory in users' home directories (for example, 'public_html' or '.').";
	}

	*(char **)apr_array_push(s_cfg->userdirs) = apr_pstrdup(cmd->pool, arg);
	return NULL;
}

static const char *
set_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);
	LDAPURLDesc *url;

#if LDAP_API_VERSION < 2000
	if (s_cfg->server) {
		return "LDAPUserDirServerURL can't be combined with LDAPUserDirServer.";
	}
#endif /* LDAP_API_VERSION < 2000 */
	if (s_cfg->basedn || s_cfg->filter_template || s_cfg->search_scope != -1) {
		return "LDAPUserDirServerURL can't be combined with LDAPUserDirBaseDN, LDAPUserDirFilter, or LDAPUserDirSearchScope.";
	}
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

	if (!SCHEME_IS("ldaps:") && !SCHEME_IS("ldap:")) {
		return "Invalid scheme specified by LDAPUserDirServerURL. Valid schemes are 'ldap' or 'ldaps'.";
	}

#ifdef TLS
	if (SCHEME_IS("ldaps:") && s_cfg->use_tls != -1) {
		return "ldaps:// scheme in LDAPUserDirServerURL can't be combined with LDAPUserDirUseTLS.";
	}
#endif /* TLS */

	ldap_free_urldesc(url);

	*(char **)apr_array_push(s_cfg->servers) = apr_pstrdup(cmd->pool, arg);
	return NULL;
}

static const char *
set_server(cmd_parms *cmd, void *dummy, const char *arg)
{
	char *word;
	ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(cmd->server->module_config, &ldap_userdir_module);

	if (s_cfg->got_url) {
		return "LDAPUserDirServer can't be combined with LDAPUserDirServerURL.";
	}

	while (*arg) {
		word = ap_getword_conf(cmd->pool, &arg);

		if (strlen(word) == 0) {
			return "LDAPUserDirServer must be supplied with the name of an LDAP server.";
		}

		*(char **)apr_array_push(s_cfg->servers) = word;
	}

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

	s_cfg->ldap_dn = (char *)dn;
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

	s_cfg->basedn = apr_pstrdup(cmd->pool, arg);
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

	s_cfg->filter_template = apr_pstrdup(cmd->pool, arg);
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
	int i;
	char *item;
	LDAPURLDesc *url;

	if (arg == 1) {
		for (i = 0; i < s_cfg->servers->nelts; ++i) {
			item = ((char **)(s_cfg->servers->elts))[i];

			if (!ldap_is_ldap_url(item)) {
				/* We default to plaintext LDAP for bare hosts. */
				continue;
			}
			if (ldap_url_parse(item, &url) != LDAP_URL_SUCCESS) {
				/* set_url should have syntax checked the URL,
				 * so this should never happen.
				 */
				continue;
			}

			if (strcasecmp(url->lud_scheme, "ldaps") == 0) {
				return "LDAPUserDirUseTLS can't be combined with ldaps:// in LDAPUserDirServerURL.";
			}
		}
	}
	if (s_cfg->protocol_version < 3 && s_cfg->protocol_version != -1) {
		return "LDAPProtocolVersion must be set to version 3 to use the LDAPUserDirUseTLS directive.";
	}

	s_cfg->use_tls = arg;
	return NULL;
#else
	return "mod_ldap_userdir was not built with LDAP TLS support.";
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
		s_cfg->home_attr = apr_pstrdup(cmd->pool, their_attr);
	} else if (strcasecmp(our_attr, "uid") == 0) {
		s_cfg->username_attr = apr_pstrdup(cmd->pool, their_attr);
	} else if (strcasecmp(our_attr, "uidNumber") == 0) {
		s_cfg->uidNumber_attr = apr_pstrdup(cmd->pool, their_attr);
	} else if (strcasecmp(our_attr, "gidNumber") == 0) {
		s_cfg->gidNumber_attr = apr_pstrdup(cmd->pool, their_attr);
	} else {
		return "LDAPAttributeName accepts only \"homeDirectory\", \"uid\", \"uidNumber\", or \"gidNumber\" for its first argument.";
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
	if (arg[0] == '\0' || *invalid_char != '\0' ||
	    (s_cfg->protocol_version != 2 && s_cfg->protocol_version != 3)) {
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
	if (!cfg->uidNumber_attr) {
		cfg->uidNumber_attr = "uidNumber";
	}
	if (!cfg->gidNumber_attr) {
		cfg->gidNumber_attr = "gidNumber";
	}
#if LDAP_API_VERSION < 2000
	if (cfg->port == -1) {
		cfg->port = LDAP_PORT;
	}
#endif /* LDAP_API_VERSION < 2000 */
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

static int
init_ldap_userdir(apr_pool_t *pconf, apr_pool_t *plog,
                  apr_pool_t *ptemp, server_rec *s)
{
	for (; s; s = s->next) {
		ldap_userdir_config *s_cfg =
			(ldap_userdir_config *) ap_get_module_config(s->module_config, &ldap_userdir_module);
		apply_config_defaults(s_cfg);
	}

	ap_add_version_component(pconf, "mod_ldap_userdir/1.1.19");
	return OK;
}

static char *
result2errmsg(const request_rec *r, LDAP *ld, LDAPMessage *result)
{
	int ret;
	char *result_errmsg, *errmsg;
#if LDAP_API_VERSION >= 2000
	ret = ldap_parse_result(ld, result, NULL, NULL, &result_errmsg,
		NULL, NULL, 0);
	if (ret == LDAP_SUCCESS) {
		errmsg = apr_pstrdup(r->pool, result_errmsg);
		ldap_memfree(result_errmsg);
	} else {
		errmsg = "Unknown";
	}
#else
	errmsg = ldap_err2string(ldap_result2error(ld, result, 0));
#endif

	return errmsg;
}

static int
_ldap_connect(ldap_userdir_config *s_cfg)
{
	int ret, sizelimit = 2, version;
#if LDAP_API_VERSION >= 2000
	struct berval bindcred;
#endif

#ifdef HAS_LDAP_INITIALIZE
	ret = ldap_initialize(&(s_cfg->ld), s_cfg->url);
	if (ret != LDAP_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_initialize() to %s failed: %s", s_cfg->url, strerror(ret));
		return -1;
	}
#else /* HAS_LDAP_INITIALIZE */
	if ((s_cfg->ld = (LDAP *) ldap_init(s_cfg->server, s_cfg->port)) == NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_init() to %s failed: %s", s_cfg->server, strerror(errno));
		return -1;
	}
#endif /* HAS_LDAP_INITIALIZE */

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
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: Setting LDAP version option failed: %s", ldap_err2string(ret));
			LDAP_UNBIND(s_cfg->ld);
			s_cfg->ld = NULL;
			return -1;
		}

#ifdef TLS
	if (s_cfg->use_tls) {
		if ((ret = ldap_start_tls_s(s_cfg->ld, NULL, NULL)) != LDAP_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: Starting TLS failed: %s", ldap_err2string(ret));
			LDAP_UNBIND(s_cfg->ld);
			s_cfg->ld = NULL;
			return -1;
		}
	}
#endif /* TLS */

#if LDAP_API_VERSION >= 2000
	bindcred.bv_val = s_cfg->dn_pass;
	if (s_cfg->dn_pass != NULL) {
		bindcred.bv_len = strlen(s_cfg->dn_pass);
	} else {
		bindcred.bv_len = 0;
	}
	ret = ldap_sasl_bind_s(s_cfg->ld, s_cfg->ldap_dn, NULL, &bindcred, NULL, NULL, NULL);
#else /* LDAP_API_VERSION >= 2000 */
	ret = ldap_simple_bind_s(s_cfg->ld, s_cfg->ldap_dn, s_cfg->dn_pass);
#endif /* LDAP_API_VERSION >= 2000 */
	if (ret != LDAP_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: bind as %s failed: %s", s_cfg->ldap_dn, ldap_err2string(ret));
		return -1;
	}

	/* I couldn't think of a better way to do this without having autoconf
	 * jump through hoops to detect whether ldap_set_option is present.
	 * I think this works fairly well, though, as we're sure to need
	 * LDAP_OPT_SIZELIMIT to use ldap_set_option in this case. :-)
	 */
#ifdef LDAP_OPT_SIZELIMIT
	if ((ret = ldap_set_option(s_cfg->ld, LDAP_OPT_SIZELIMIT, (void *)&sizelimit)) != LDAP_OPT_SUCCESS)
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: ldap_set_option() unable to set query size limit to 2 entries: %s", ldap_err2string(ret));
#else /* LDAP_OPT_SIZELIMIT */
	s_cfg->ld->ld_sizelimit = sizelimit;
#endif /* LDAP_OPT_SIZELIMIT */

	return 1;
}

static int
connect_ldap_userdir(request_rec *r, ldap_userdir_config *s_cfg)
{
	int start_server_index;
	char *item;
	LDAPURLDesc *url;

	start_server_index = s_cfg->cur_server_index;
	do {
		/* We won't have any configured servers if no
		 * LDAPUserDirServer* directives were specified.
		 * Fall back and use the SDK default if so.
		 */
		if (s_cfg->servers->nelts) {
			item = ((char **)(s_cfg->servers->elts))[s_cfg->cur_server_index];

			if (ldap_is_ldap_url(item)) {
				if (ldap_url_parse(item, &url) != LDAP_URL_SUCCESS) {
					ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: URL %s was valid at startup, but is no longer valid?!", item);

					++(s_cfg->cur_server_index);
					if (s_cfg->cur_server_index >= s_cfg->servers->nelts) {
						s_cfg->cur_server_index = 0;
					}
					continue;
				}

#ifdef HAS_LDAP_INITIALIZE
				s_cfg->url = apr_pstrdup(r->server->process->pool, item);
#else /* HAS_LDAP_INITIALIZE */
				if (url->lud_host != NULL) {
					s_cfg->server = apr_pstrdup(r->server->process->pool, url->lud_host);
				}
				if (url->lud_port != 0) {
					s_cfg->port = url->lud_port;
				}
#endif /* HAS_LDAP_INITIALIZE */
				if (url->lud_dn != NULL) {
					s_cfg->basedn = apr_pstrdup(r->server->process->pool, url->lud_dn);
				}
				if (url->lud_filter != NULL) {
					s_cfg->filter_template = apr_pstrdup(r->server->process->pool, url->lud_filter);
				}

				s_cfg->search_scope = url->lud_scope;
				if (s_cfg->search_scope == LDAP_SCOPE_BASE) {
					ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, 0, NULL, "mod_ldap_userdir: WARNING: LDAP URL search scopes default to 'base' (not 'sub') and may not be what you want.");
				}

				ldap_free_urldesc(url);
			} else {
#ifdef HAS_LDAP_INITIALIZE
				s_cfg->url = apr_pstrcat(r->server->process->pool,
					"ldap://", item, "/", NULL);
#else /* HAS_LDAP_INITIALIZE */
				s_cfg->server = apr_pstrdup(r->server->process->pool, item);
				s_cfg->port = LDAP_PORT;
#endif /* HAS_LDAP_INITIALIZE */
			}
		}

		if (_ldap_connect(s_cfg) == 1) {
			return 1;
		}

		++s_cfg->cur_server_index;
		if (s_cfg->cur_server_index >= s_cfg->servers->nelts) {
			s_cfg->cur_server_index = 0;
		}
	} while (s_cfg->cur_server_index != start_server_index);

	return -1;
}

static char *
generate_filter(apr_pool_t *p, char *template, const char *entity)
{
	char *filter, *pos;
	int num_escapes = 0, i = 0, j = 0;

	pos = template;
	while ((pos = ap_strstr(pos + 2, "%v")) != NULL) {
		++num_escapes;
	}
	pos = template;
	while ((pos = ap_strstr(pos + 2, "%u")) != NULL) {
		++num_escapes;
	}

	/* -2 for the %u/%v, +1 for the NULL */
	filter = apr_pcalloc(p, strlen(template) - (num_escapes * 2) + (num_escapes * strlen(entity)) + 1);

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

void
free_entry(struct hash_entry **entry)
{
	if (!*entry) {
		return;
	}

	if ((*entry)->homedir) {
		free((*entry)->homedir);
	}
	if ((*entry)->posix_username) {
		free((*entry)->posix_username);
	}
	if ((*entry)->uid) {
		free((*entry)->uid);
	}
	if ((*entry)->gid) {
		free((*entry)->gid);
	}

	free((*entry));
	*entry = NULL;
}

static struct hash_entry *
cache_fetch(const ldap_userdir_config *s_cfg, const char *username)
{
	struct hash_entry *entry;

	/* A cache timeout of 0 disables caching. */
	if (s_cfg->cache_timeout == 0) {
		return NULL;
	}

	entry = apr_hash_get(s_cfg->homedirHt, username, APR_HASH_KEY_STRING);
	if (entry == NULL) {
		return NULL;
	}

	/* If this entry is still valid, return it. Otherwise, expire the
	 * stale entry.
	 */
	if (entry->inserted_at + s_cfg->cache_timeout > time(NULL)) {
		return entry;
	}

	free_entry(&entry);
	apr_hash_set(s_cfg->homedirHt, username, APR_HASH_KEY_STRING, NULL);
	return NULL;
}

static struct hash_entry *
get_ldap_homedir(ldap_userdir_config *s_cfg, request_rec *r,
                 const char *username)
{
	char *filter,
	     *attrs[] = {s_cfg->home_attr, s_cfg->username_attr,
	                 s_cfg->uidNumber_attr, s_cfg->gidNumber_attr, NULL};
	int i = 0, ret;
#if LDAP_API_VERSION >= 2000
	struct timeval timeout;
	struct berval **values;
#else
	char **values;
#endif
	LDAPMessage *result, *e;
	struct hash_entry *entry;

	entry = cache_fetch(s_cfg, username);
	if (entry != NULL) {
		return entry;
	}

	/* If we haven't even connected yet, try to connect. If we still can't
	   connect, give up. */
	if (s_cfg->ld == NULL) {
		if (connect_ldap_userdir(r, s_cfg) != 1) {
			return NULL;
		}
	}

	if (s_cfg->filter_template && *(s_cfg->filter_template)) {
		filter = generate_filter(r->pool, s_cfg->filter_template, username);
	} else {
		filter = generate_filter(r->pool, "(&(uid=%u)(objectClass=posixAccount))", username);
	}

#if LDAP_API_VERSION >= 2000
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	ret = ldap_search_ext_s(s_cfg->ld, s_cfg->basedn, s_cfg->search_scope,
		filter, attrs, 0, NULL, NULL, &timeout, 2, &result);
#else /* LDAP_API_VERSION >= 2000 */
	ret = ldap_search_s(s_cfg->ld, s_cfg->basedn, s_cfg->search_scope,
		filter, attrs, 0, &result);
#endif /* LDAP_API_VERSION >= 2000 */
	if (ret != LDAP_SUCCESS) {
		/* If the LDAP server went away, try to reconnect. If the reconnect
		 * fails, give up and log accordingly.
		 */
		if (ret == LDAP_SERVER_DOWN) {
			LDAP_UNBIND(s_cfg->ld);

			if (connect_ldap_userdir(r, s_cfg) != 1) {
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: LDAP server went away, couldn't reconnect. Declining request.");
				s_cfg->ld = NULL;
				return NULL;
			}

#if LDAP_API_VERSION >= 2000
			ret = ldap_search_ext_s(s_cfg->ld, s_cfg->basedn, s_cfg->search_scope,
				filter, attrs, 0, NULL, NULL, &timeout, 2, &result);
#else /* LDAP_API_VERSION >= 2000 */
			ret = ldap_search_s(s_cfg->ld, s_cfg->basedn, s_cfg->search_scope,
				filter, attrs, 0, &result);
#endif /* LDAP_API_VERSION >= 2000 */
			if (ret != LDAP_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: LDAP search failed: %s", ldap_err2string(ret));
				return NULL;
			}
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: LDAP search failed: %s", ldap_err2string(ret));
			return NULL;
		}
	}

	if ((ret = ldap_count_entries(s_cfg->ld, result)) > 1) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: found too many entries (%d entries) for query, expecting 1 entry. Ignoring LDAP results.", ret);
		ldap_msgfree(result);
		return NULL;
	} else if (ret < 1) {
		/* We didn't find any users, don't bother calling ldap_first_entry(). */
		return NULL;
	}

	if ((e = ldap_first_entry(s_cfg->ld, result)) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_first_entry() failed: %s", result2errmsg(r, s_cfg->ld, result));
		ldap_msgfree(result);
		return NULL;
	}

	entry = (struct hash_entry *) calloc(1, sizeof(struct hash_entry));
	if (entry == NULL) {
		ldap_msgfree(result);
		return NULL;
	}

	while (attrs[i] != NULL) {
#if LDAP_API_VERSION >= 2000
		values = ldap_get_values_len(s_cfg->ld, e, attrs[i]);
#else
		values = ldap_get_values(s_cfg->ld, e, attrs[i]);
#endif
		if (!values) {
			if (strcmp(attrs[i], s_cfg->username_attr) == 0 ||
			    strcmp(attrs[i], s_cfg->home_attr) == 0)
			{
				ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: user %s has no %s attr, skipping request.", username, attrs[i]);
				free_entry(&entry);
				ldap_msgfree(result);
				return NULL;
			}
			++i;
			continue;
		}

		/* There doesn't seem to be any per-server/thread pool we can use
		 * here, so we need to jump through some hoops to make sure we
		 * don't leak if anything fails.
		 */
		if (strcmp(attrs[i], s_cfg->home_attr) == 0) {
			entry->homedir = strdup(LDAP_VALUE(values, 0));
			LDAP_VALUE_FREE(values);
			if (entry->homedir == NULL) {
				free_entry(&entry);
				ldap_msgfree(result);
				return NULL;
			}
		} else if (strcmp(attrs[i], s_cfg->username_attr) == 0) {
			entry->posix_username = strdup(LDAP_VALUE(values, 0));
			LDAP_VALUE_FREE(values);
			if (entry->posix_username == NULL) {
				free_entry(&entry);
				ldap_msgfree(result);
				return NULL;
			}
		} else if (strcmp(attrs[i], s_cfg->uidNumber_attr) == 0) {
			entry->uid = strdup(LDAP_VALUE(values, 0));
			LDAP_VALUE_FREE(values);
			if (entry->uid == NULL) {
				free_entry(&entry);
				ldap_msgfree(result);
				return NULL;
			}
		} else if (strcmp(attrs[i], s_cfg->gidNumber_attr) == 0) {
			entry->gid = strdup(LDAP_VALUE(values, 0));
			LDAP_VALUE_FREE(values);
			if (entry->gid == NULL) {
				free_entry(&entry);
				ldap_msgfree(result);
				return NULL;
			}
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r, "mod_ldap_userdir: ldap_get_values() loop found unknown attr %s", attrs[i]);
			LDAP_VALUE_FREE(values);
		}

		++i;
	}

	/* A cache timeout of 0 disables caching. */
	if (s_cfg->cache_timeout != 0) {
		entry->inserted_at = time(NULL);
		apr_hash_set(s_cfg->homedirHt, entry->posix_username,
			APR_HASH_KEY_STRING, entry);
	}

	ldap_msgfree(result);
	return entry;
}

static int
translate_ldap_userdir(request_rec *r)
{
	const char *w, *dname;
	char *name = r->uri;
	int userdir_index;
	const ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(r->server->module_config, &ldap_userdir_module);
	request_rec *notes_req;
	struct hash_entry *user_info;

	/* If the URI doesn't match our basic pattern, we've nothing to do
	 * with it.
	 */
	if ((s_cfg->userdirs->nelts == 0) ||
	    (name[0] != '/') ||
	    (name[1] != '~'))
	{
		return DECLINED;
	}

	dname = name + 2;
	w = ap_getword(r->pool, &dname, '/');

	/* This 'dname' funny business involves backing it up to capture the '/'
	 * delimiting the "/~user" part from the rest of the URL, in case there
	 * was one (the case where there wasn't being just "GET /~user HTTP/1.0",
	 * for which we don't want to tack on a '/' onto the filename).
	 */
	if (dname[-1] == '/') {
		--dname;
	}

	/* If there's no username, it's not for us. Ignore . and .. as well. */
	if (w[0] == '\0' || (w[1] == '.' && (w[2] == '\0' || (w[2] == '.' && w[3] == '\0')))) {
		return DECLINED;
	}

	user_info = get_ldap_homedir((ldap_userdir_config *)s_cfg, r, w);
	if (user_info == NULL) {
		return DECLINED;
	}

	userdir_index = 0;
	while (userdir_index < s_cfg->userdirs->nelts) {
		const char *userdir = ((char **)(s_cfg->userdirs->elts))[userdir_index];
		++userdir_index;
		char *filename;
		apr_finfo_t statbuf;
		apr_status_t rv;
		int is_absolute = ap_os_is_path_absolute(r->pool, userdir);
		char *x = NULL, *redirect;

		if (ap_strchr_c(userdir, '*')) {
			x = ap_getword(r->pool, &userdir, '*');
		}

		if (userdir[0] == '\0' || is_absolute) {
			if (x) {
				if (ap_strstr_c(x, "://") && !is_absolute)	{
					redirect = apr_pstrcat(r->pool, x, w, userdir, dname, NULL);
					apr_table_setn(r->headers_out, "Location", redirect);
					return HTTP_MOVED_TEMPORARILY;
				} else {
					filename = apr_pstrcat(r->pool, x, w, userdir, NULL);
				}
			} else {
				filename = apr_pstrcat(r->pool, userdir, "/", w, NULL);
			}
		} else if (x && ap_strstr_c(x, "://")) {
			redirect = apr_pstrcat(r->pool, x, w, userdir, dname, NULL);
			apr_table_setn(r->headers_out, "Location", redirect);
			return HTTP_MOVED_TEMPORARILY;
		} else {
			filename = apr_pstrcat(r->pool, user_info->homedir, "/", userdir, NULL);
		}

		/* Now see if it exists, or we're at the last entry. If we're
		 * at the last entry, then use the filename generated (if there
		 * is one) anyway, in the hope that some handler might handle
		 * it. This can be used, for example, to run a CGI script for
		 * the user.
		 */
		if (filename &&
		    (userdir_index >= s_cfg->userdirs->nelts ||
		     ((rv = apr_stat(&statbuf, filename, APR_FINFO_MIN, r->pool)) == APR_SUCCESS ||
		      rv == APR_INCOMPLETE))) {

			r->filename = apr_pstrcat(r->pool, filename, dname, NULL);
			/* When statbuf contains info on r->filename, we can save
			 * a syscall by copying it to r->finfo.
			 */
			if (userdir_index < s_cfg->userdirs->nelts && dname[0] == 0) {
				r->finfo = statbuf;
			}

			/* We could be servicing a sub-request; make sure we put notes
			 * on the main request.
			 */
			if (r->main) {
				notes_req = r->main;
			} else {
				notes_req = r;
			}
			/* For use in the get_suexec_identity phase. */
			apr_table_setn(notes_req->notes, "mod_ldap_userdir_user", user_info->posix_username);
			apr_table_setn(notes_req->notes, "mod_ldap_userdir_uid", user_info->uid);
			apr_table_setn(notes_req->notes, "mod_ldap_userdir_gid", user_info->gid);

			return OK;
		}
	}

	return DECLINED;
}

#ifdef HAVE_UNIX_SUEXEC
static ap_unix_identity_t *get_suexec_id_doer(const request_rec *r)
{
	const char *username = apr_table_get(r->notes, "mod_ldap_userdir_user"),
	           *uidNumber = apr_table_get(r->notes, "mod_ldap_userdir_uid"),
	           *gidNumber = apr_table_get(r->notes, "mod_ldap_userdir_gid");
	char *endptr = NULL;
	const ldap_userdir_config *s_cfg = (ldap_userdir_config *) ap_get_module_config(r->server->module_config, &ldap_userdir_module);
	ap_unix_identity_t *ugid;

	if (!username) {
		return NULL;
	}
	if (!uidNumber) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: user %s has no %s attr, ignoring suexec request.", username, s_cfg->uidNumber_attr);
		return NULL;
	}

	if (!gidNumber) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: user %s has no %s attr, ignoring suexec request.", username, s_cfg->gidNumber_attr);
		return NULL;
	}

	ugid = apr_palloc(r->pool, sizeof(ap_unix_identity_t *));
	if (ugid == NULL) {
		return NULL;
	}

	ugid->uid = (uid_t) strtoul(uidNumber, &endptr, 10);
	if (*endptr != '\0') {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: user %s has invalid UID %s, ignoring suexec request.", username, uidNumber);
		return NULL;
	}
	ugid->gid = (gid_t) strtoul(gidNumber, &endptr, 10);
	if (*endptr != '\0') {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_ldap_userdir: user %s has invalid GID %s, ignoring suexec request.", username, gidNumber);
		return NULL;
	}

	ugid->userdir = 1;
	return ugid;
}
#endif /* HAVE_UNIX_SUEXEC */

static void
register_hooks(apr_pool_t *p)
{
	static const char *const aszPre[]  = {"mod_alias.c",       NULL};
	static const char *const aszSucc[] = {"mod_vhost_alias.c", NULL};
	ap_hook_translate_name(translate_ldap_userdir, aszPre, aszSucc, APR_HOOK_MIDDLE);

	ap_hook_post_config(init_ldap_userdir, NULL, NULL, APR_HOOK_MIDDLE);

#ifdef HAVE_UNIX_SUEXEC
	ap_hook_get_suexec_identity(get_suexec_id_doer, NULL, NULL, APR_HOOK_FIRST);
#endif
}

static const command_rec ldap_userdir_cmds[] = {
	AP_INIT_ITERATE("LDAPUserDir", set_ldap_user_dir, NULL, RSRC_CONF,
	                 "the public subdirectory in users' home directories"),
	AP_INIT_ITERATE("LDAPUserDirServer", set_server, NULL, RSRC_CONF,
	              "the LDAP directory server that will be used for LDAP UserDir queries"),
	AP_INIT_ITERATE("LDAPUserDirServerURL", set_url, NULL, RSRC_CONF,
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
	{NULL}
};

module AP_MODULE_DECLARE_DATA ldap_userdir_module = {
	STANDARD20_MODULE_STUFF,
	NULL,                        /* dir config creater */
	NULL,                        /* dir merger --- default is to override */
	create_ldap_userdir_config,  /* server config */
	merge_ldap_userdir_config,   /* merge server config */
	ldap_userdir_cmds,           /* command table */
	register_hooks               /* register hooks */
};
