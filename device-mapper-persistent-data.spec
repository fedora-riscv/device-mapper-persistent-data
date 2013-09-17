#
# Copyright (C) 2011-2013 Red Hat, Inc
#
Summary: Device-mapper thin provisioning tools
Name: device-mapper-persistent-data
Version: 0.2.7
Release: 1%{?dist}
License: GPLv3+
Group: System Environment/Base
URL: https://github.com/jthornber/thin-provisioning-tools
Source0: https://github.com/jthornber/thin-provisioning-tools/archive/thin-provisioning-tools-v%{version}.tar.bz2
# Source1: https://github.com/jthornber/thin-provisioning-tools/archive/v%{version}.tar.gz
BuildRequires: autoconf, expat-devel, libstdc++-devel, boost-devel
Requires: expat

%description
thin-provisioning-tools contains check,dump,restore,repair,rmap and metadata_size
tools to manage device-mapper thin provisioning target metadata devices or
metadata on files.

%prep
%setup -q -n thin-provisioning-tools-%{version}
echo %{version}-%{release} > VERSION

%build
autoconf
%configure --with-optimisation=
make %{?_smp_mflags} V=

%install
make DESTDIR=%{buildroot} MANDIR=%{_mandir} install

%clean

%files
%doc COPYING README.md
%{_mandir}/man8/thin_check.8.gz
%{_mandir}/man8/thin_dump.8.gz
%{_mandir}/man8/thin_metadata_size.8.gz
%{_mandir}/man8/thin_repair.8.gz
%{_mandir}/man8/thin_restore.8.gz
%{_mandir}/man8/thin_rmap.8.gz
%{_sbindir}/thin_check
%{_sbindir}/thin_dump
%{_sbindir}/thin_metadata_size
%{_sbindir}/thin_repair
%{_sbindir}/thin_restore
%{_sbindir}/thin_rmap

%changelog
* Wed Jul 31 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.7-1
- New upstream version 0.2.7

* Wed Jul 31 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.3-1
- New upstream version

* Fri Jul 12 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.1-1
- New upstream version.

* Wed Jul 18 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.1.4-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Thu Apr 19 2012 Milan Broz <mbroz@redhat.com> - 0.1.4-1
- Fix thin_check man page (add -q option).
- Install utilities in /usr/sbin.

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
