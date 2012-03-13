#
# Copyright (C) 2011-2012 Red Hat, Inc
#
Summary: Device-mapper thin provisioning tools
Name: device-mapper-persistent-data
Version: 0.1.2
Release: 1%{?dist}
License: GPLv3+
Group: System Environment/Base
URL: https://github.com/jthornber/thin-provisioning-tools
Source0: https://github.com/downloads/jthornber/thin-provisioning-tools/thin-provisioning-tools-v%{version}.tar.bz2
BuildRequires: expat-devel, libstdc++-devel, boost-devel
Requires: expat

%description
thin-provisioning-tools contains dump,restore and repair tools to
manage device-mapper thin provisioning target metadata devices.

%prep
%setup -q -n thin-provisioning-tools-v%{version}

%build
%global _root_sbindir /sbin
%configure --enable-debug --enable-testing
make %{?_smp_mflags}

%install
make DESTDIR=%{buildroot} MANDIR=%{_mandir} install

%clean

%files
%doc COPYING README
%{_mandir}/man8/thin_dump.8.gz
%{_mandir}/man8/thin_check.8.gz
%{_mandir}/man8/thin_restore.8.gz
%{_root_sbindir}/thin_dump
%{_root_sbindir}/thin_check
%{_root_sbindir}/thin_restore

%changelog
* Tue Mar 13 2012 Milan Broz <mbroz@redhat.com> - 0.1.2-1
- New upstream version.

* Mon Mar 05 2012 Milan Broz <mbroz@redhat.com> - 0.1.1-1
- Fix quiet option.

* Fri Mar 02 2012 Milan Broz <mbroz@redhat.com> - 0.1.0-1
- New upstream version.

* Tue Feb 28 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.0.1-3
- Rebuilt for c++ ABI breakage

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.0.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Wed Dec 21 2011 Milan Broz <mbroz@redhat.com> - 0.0.1-1
- Initial version
