#
# Copyright (C) 2011-2014 Red Hat, Inc
#
Summary: Device-mapper Persistent Data Tools
Name: device-mapper-persistent-data
Version: 0.4.1
Release: 1%{?dist}
License: GPLv3+
Group: System Environment/Base
URL: https://github.com/jthornber/thin-provisioning-tools
Source0: https://github.com/jthornber/thin-provisioning-tools/archive/thin-provisioning-tools-v%{version}.tar.bz2
# Source1: https://github.com/jthornber/thin-provisioning-tools/archive/v%{version}.tar.gz
BuildRequires: autoconf, expat-devel, libaio-devel, libstdc++-devel, boost-devel
Requires: expat
Patch0: device-mapper-persistent-data-0.4.1-bz1085620.patch
Patch1: device-mapper-persistent-data-0.4.1-missing-man-pages.patch

%description
thin-provisioning-tools contains check,dump,restore,repair,rmap
and metadata_size tools to manage device-mapper thin provisioning
target metadata devices; cache check,dump,metadata_size,restore
and repair tools to manage device-mapper cache metadata devices
are included and era check, dump, restore and invalidate to manage
snapshot eras

%prep
%setup -q -n thin-provisioning-tools-%{version}
%patch0 -p1
%patch1 -p1
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
%{_mandir}/man8/cache_check.8.gz
%{_mandir}/man8/cache_dump.8.gz
%{_mandir}/man8/cache_restore.8.gz
%{_mandir}/man8/cache_repair.8.gz
%{_mandir}/man8/era_check.8.gz
%{_mandir}/man8/era_dump.8.gz
%{_mandir}/man8/era_invalidate.8.gz
%{_mandir}/man8/thin_check.8.gz
%{_mandir}/man8/thin_dump.8.gz
%{_mandir}/man8/thin_metadata_size.8.gz
%{_mandir}/man8/thin_restore.8.gz
%{_mandir}/man8/thin_repair.8.gz
%{_mandir}/man8/thin_rmap.8.gz
%{_sbindir}/pdata_tools
%{_sbindir}/cache_check
%{_sbindir}/cache_dump
%{_sbindir}/cache_metadata_size
%{_sbindir}/cache_restore
%{_sbindir}/cache_repair
%{_sbindir}/era_check
%{_sbindir}/era_dump
%{_sbindir}/era_restore
%{_sbindir}/era_invalidate
%{_sbindir}/thin_check
%{_sbindir}/thin_dump
%{_sbindir}/thin_metadata_size
%{_sbindir}/thin_restore
%{_sbindir}/thin_repair
%{_sbindir}/thin_rmap

%changelog
* Tue Oct 28 2014 Heinz Mauelshagen <heinzm@redhat.com> - 0.4.1-1
- New upstream version
- Manual header additions/fixes

* Sat Aug 16 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.3.2-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.3.2-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Thu May 22 2014 Petr Machata <pmachata@redhat.com> - 0.3.2-2
- Rebuild for boost 1.55.0

* Fri Apr 11 2014 Heinz Mauelshagen <heinzm@redhat.com> - 0.3.2-1
- New upstream version 0.3.2 fixing needs_check flag processing

* Thu Mar 27 2014 Heinz Mauelshagen <heinzm@redhat.com> - 0.3.0-1
- New upstream version 0.3.0 introducing era_{check,dump,invalidate}

* Fri Oct 18 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.8-1
- New upstream version 0.2.8 introducing cache_{check,dump,repair,restore}

* Tue Sep 17 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.7-1
- New upstream version 0.2.7

* Wed Jul 31 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.3-1
- New upstream version

* Tue Jul 30 2013 Dennis Gilmore <dennis@ausil.us> - 0.2.2-2
- rebuild against boost 1.54.0

* Tue Jul 30 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.2-1
- New upstream version
- manual header fixes 

* Tue Jul 30 2013 Petr Machata <pmachata@redhat.com> - 0.2.1-6
- Rebuild for boost 1.54.0

* Thu Jul 25 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.1-5
- enhance manual pages and fix typos

* Fri Jul 18 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.1-4
- Update thin_metadata_size manual page
- thin_dump: support dumping default metadata snapshot

* Thu Jul 18 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.1-3
- New thin_metadata_size tool to estimate amount of metadata space
  based on block size, pool size and maximum amount of thin devs and snapshots
- support metadata snapshots in thin_dump tool
- New man pages for thin_metadata_size, thin_repair and thin_rmap and man page fixes

* Tue Jul 16 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.1-2
- Build with nostrip fix from Ville Skyttä

* Mon Jul 15 2013 Ville Skyttä <ville.skytta@iki.fi> - 0.2.1-2
- Let rpmbuild strip binaries, don't override optflags, build more verbose.

* Fri Jul 12 2013 Heinz Mauelshagen <heinzm@redhat.com> - 0.2.1-1
- New upstream version.

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 0.1.4-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

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
