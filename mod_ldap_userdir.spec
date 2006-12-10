#	conditional build:	
#		'_with_tls'	if	'--with tls'
#	e.g.,
#		'rpmbuild --with tls -bt mod_ldap_userdir-1.1.5.tar.bz2'

%define		__module_name	ldap_userdir

Name:		mod_%{__module_name}
Version:	1.1.5
Release:	1
URL:		http://horde.net/~jwm/software/mod_ldap_userdir/
Source:		%{name}-%{version}.tar.bz2
Source1:	%{__module_name}.conf
Group:		System Environment/Daemons
License:	GPL
Requires:	httpd
BuildRequires:	httpd-devel
Requires:	openldap
BuildRequires:	openldap-devel
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root
Summary:	Apache module for looking up /~user URLs from an LDAP directory.

%description
The mod_ldap_userdir package enables the Apache web server to look
up user home directories (for /~user URLs) from an LDAP directory.
It is authored by John Morrissey <jwm@horde.net>.

%define		__httpd_modules	%(apxs -q LIBEXECDIR)
%define		__httpd_conf_d	%(apxs -q SYSCONFDIR).d

%prep
%setup		-q

%build
./configure	--with-activate	\
		--with-apxs	\
		%{?_with_tls:--with-tls}
make

%install
[ "$RPM_BUILD_ROOT" != "/" ]	&&	rm	-rf ${RPM_BUILD_ROOT}
#apxs -i -a -n %{__module_name} %{name}.so
install		-d			${RPM_BUILD_ROOT}%{__httpd_modules}
install		-m 755	%{name}.so	${RPM_BUILD_ROOT}%{__httpd_modules}
install		-d			${RPM_BUILD_ROOT}%{__httpd_conf_d}
install		-m 644	%{SOURCE1}	${RPM_BUILD_ROOT}%{__httpd_conf_d}

%clean
[ "$RPM_BUILD_ROOT" != "/" ]	&&	rm	-rf ${RPM_BUILD_ROOT}

%post
#apxs -e -a -n %{__module_name} %{name}.so
echo		-e	!!!	'\t'	Please modify %{__httpd_conf_d}/%{__module_name}.conf	'\t'	!!!
echo		-e	!!!	'\t'	according to your LDAP settings before restarting Apache		'\t'	!!!

%files
%defattr(-,root,root)
%{__httpd_modules}/%{name}.so
%{__httpd_conf_d}/%{__module_name}.conf

%changelog
