License:        BSD
Vendor:         Otus
Group:          PD01
URL:            http://otus.ru/lessons/3/
Source0:        otus-%{current_datetime}.tar.gz
BuildRoot:      %{_tmppath}/otus-%{current_datetime}
Name:           ip2w
Version:        0.0.1
Release:        1
BuildArch:      noarch
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: systemd
Requires: systemd, nginx, python3.9
Summary:  Tutorial uwsgi service providing wether information for ip address. 

%description
This is a simple tutorial uwsgi python application implementing service that provides various information for ip address:
ip details iteself (ipinfo method)  and various weather information (wether, onecall) at geo location taken from ip address.
Git version: %{git_version} (branch: %{git_branch})

%define __config    package_config
%define __etcdir    /usr/local/etc/ip2w
%define __logdir    /var/log/ip2w
%define __bindir    /usr/local/ip2w
%define __systemddir /usr/lib/systemd/system
%define __nginxconf /etc/nginx/conf.d

%prep
%setup -q -n otus-%{current_datetime}
%install
[ "%{buildroot}" != "/" ] && rm -fr %{buildroot}
%{__mkdir} -p %{buildroot}/%{__systemddir}
%{__mkdir} -p %{buildroot}/%{__etcdir}
%{__mkdir} -p %{buildroot}/%{__logdir}
%{__mkdir} -p %{buildroot}/%{__bindir}

%{__install} -pD -m 644  %{__config}/%{name}.service %{buildroot}/%{__systemddir}/%{name}.service
%{__install} -pD -m 644  %{name}.py %{buildroot}/%{__bindir}/%{name}.py
%{__install} -pD -m 644  requirements.txt %{buildroot}/%{__bindir}/requirements.txt
%{__install} -pD -m 644  %{__config}/%{name}.uwsgi.ini %{buildroot}/%{__bindir}/%{name}.uwsgi.ini
%{__install} -pD -m 644  %{__config}/%{name}.nginx.conf %{buildroot}/%{__nginxconf}/%{name}.nginx.conf
%{__install} -pD -m 644  %{__config}/%{name}.env %{buildroot}/%{__etcdir}/%{name}.env

%post
%systemd_post %{name}.service
systemctl daemon-reload

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun %{name}.service

%clean
[ "%{buildroot}" != "/" ] && rm -fr %{buildroot}

%files
%{__logdir}
%{__systemddir}/%{name}.service
%{__bindir}/%{name}.py
%{__bindir}/requirements.txt
%{__bindir}/%{name}.uwsgi.ini
%{__nginxconf}/%{name}.nginx.conf
%{__etcdir}/%{name}.env
