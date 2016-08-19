
Name: app-firewall
Epoch: 1
Version: 2.2.12
Release: 1%{dist}
Summary: Firewall
License: GPLv3
Group: ClearOS/Apps
Source: %{name}-%{version}.tar.gz
Buildarch: noarch
Requires: %{name}-core = 1:%{version}-%{release}
Requires: app-base
Requires: app-network >= 1:2.1.13

%description
The core firewall engine for the system.

%package core
Summary: Firewall - Core
License: LGPLv3
Group: ClearOS/Libraries
Requires: app-base-core
Requires: app-events-core
Requires: csplugin-events >= 1.0-26
Requires: app-network-core
Requires: csplugin-filewatch
Requires: firewall >= 1.4.21-9
Requires: iptables
Requires: csplugin-events
Obsoletes: iptables-services

%description core
The core firewall engine for the system.

This package provides the core API and libraries.

%prep
%setup -q
%build

%install
mkdir -p -m 755 %{buildroot}/usr/clearos/apps/firewall
cp -r * %{buildroot}/usr/clearos/apps/firewall/

install -d -m 0755 %{buildroot}/etc/clearos/firewall.d
install -d -m 0755 %{buildroot}/var/clearos/firewall
install -d -m 0755 %{buildroot}/var/state/firewall
install -D -m 0644 packaging/filewatch-firewall.conf %{buildroot}/etc/clearsync.d/filewatch-firewall.conf
install -D -m 0755 packaging/firewall-start %{buildroot}/usr/sbin/firewall-start
install -D -m 0644 packaging/firewall.conf %{buildroot}/etc/clearos/firewall.conf
install -D -m 0755 packaging/local %{buildroot}/etc/clearos/firewall.d/local
install -D -m 0755 packaging/network-proxy-event %{buildroot}/var/clearos/events/network_proxy/firewall
install -D -m 0755 packaging/types %{buildroot}/etc/clearos/firewall.d/types
ln -s /usr/sbin/firewall-start %{buildroot}/usr/sbin/firewall-start6

%post
logger -p local6.notice -t installer 'app-firewall - installing'

%post core
logger -p local6.notice -t installer 'app-firewall-core - installing'

if [ $1 -eq 1 ]; then
    [ -x /usr/clearos/apps/firewall/deploy/install ] && /usr/clearos/apps/firewall/deploy/install
fi

[ -x /usr/clearos/apps/firewall/deploy/upgrade ] && /usr/clearos/apps/firewall/deploy/upgrade

exit 0

%preun
if [ $1 -eq 0 ]; then
    logger -p local6.notice -t installer 'app-firewall - uninstalling'
fi

%preun core
if [ $1 -eq 0 ]; then
    logger -p local6.notice -t installer 'app-firewall-core - uninstalling'
    [ -x /usr/clearos/apps/firewall/deploy/uninstall ] && /usr/clearos/apps/firewall/deploy/uninstall
fi

exit 0

%files
%defattr(-,root,root)
/usr/clearos/apps/firewall/views

%files core
%defattr(-,root,root)
%exclude /usr/clearos/apps/firewall/packaging
%dir /usr/clearos/apps/firewall
%dir /etc/clearos/firewall.d
%dir /var/clearos/firewall
%dir /var/state/firewall
/usr/clearos/apps/firewall/deploy
/usr/clearos/apps/firewall/language
/usr/clearos/apps/firewall/libraries
/etc/clearsync.d/filewatch-firewall.conf
/usr/sbin/firewall-start
%config(noreplace) /etc/clearos/firewall.conf
%config(noreplace) /etc/clearos/firewall.d/local
/var/clearos/events/network_proxy/firewall
/etc/clearos/firewall.d/types
/usr/sbin/firewall-start6
