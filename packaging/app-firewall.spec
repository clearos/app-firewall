
Name: app-firewall
Group: ClearOS/Apps
Version: 5.9.9.1
Release: 1%{dist}
Summary: Firewall configuration tool
License: GPLv3
Packager: ClearFoundation
Vendor: ClearFoundation
Source: %{name}-%{version}.tar.gz
Buildarch: noarch
Requires: %{name}-core = %{version}-%{release}
Requires: app-base
Requires: app-network

%description
Firewall description... blah blah

%package core
Summary: Firewall configuration tool - APIs and install
Group: ClearOS/Libraries
License: LGPLv3
Requires: app-base-core
Requires: app-network-core
Requires: iptables

%description core
Firewall description... blah blah

This package provides the core API and libraries.

%prep
%setup -q
%build

%install
mkdir -p -m 755 %{buildroot}/usr/clearos/apps/firewall
cp -r * %{buildroot}/usr/clearos/apps/firewall/

install -D -m 0755 packaging/firewall-up %{buildroot}/usr/sbin/firewall-up

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
/usr/clearos/apps/firewall/controllers
/usr/clearos/apps/firewall/htdocs
/usr/clearos/apps/firewall/views

%files core
%defattr(-,root,root)
%exclude /usr/clearos/apps/firewall/packaging
%exclude /usr/clearos/apps/firewall/tests
%dir /usr/clearos/apps/firewall
/usr/clearos/apps/firewall/deploy
/usr/clearos/apps/firewall/language
/usr/clearos/apps/firewall/libraries
/usr/sbin/firewall-up
