#
# Copyright (C) 2011 Red Hat, Inc
#
Summary: Device-mapper thin provisioning tools
Name: device-mapper-persistent-data
Version: 0.0.1
Release: 1%{?dist}
License: GPLv3+
Group: System Environment/Base
URL: https://github.com/jthornber/thin-provisioning-tools
BuildRequires: expat-devel, libstdc++-devel, boost-devel, autoconf, automake

# The source for this package was pulled from upstream's git.
# Use the following URL to access the tarball:
# https://github.com/jthornber/thin-provisioning-tools/tarball/%%{version}
%global upstream_tag 4dcab4b
%global upstream_version %{version}-0-g%{upstream_tag}

Source0: jthornber-thin-provisioning-tools-%{upstream_version}.tar.gz
Requires: expat

%description
thin-provisioning-tools contains dump,restore and repair tools to
manage device-mapper thin provisioning target metadata devices.

%prep
%setup -q -n jthornber-thin-provisioning-tools-%{upstream_tag}
autoreconf

%build
%global _root_sbindir /sbin
%configure --enable-debug --enable-testing

%install
make DESTDIR=%{buildroot} MANDIR=%{_mandir} install

%clean

%files
%doc COPYING README
%{_mandir}/man8/thin_dump.8.gz
%{_mandir}/man8/thin_repair.8.gz
%{_mandir}/man8/thin_restore.8.gz
%{_root_sbindir}/thin_dump
%{_root_sbindir}/thin_repair
%{_root_sbindir}/thin_restore

%changelog
* Wed Dec 21 2011 Milan Broz <mbroz@redhat.com> - 0.0.1-1
- Initial version
