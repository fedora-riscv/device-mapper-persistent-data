# Packaging dmpd

This is mostly regular package except recent addition of rust to used languages.

## rust-tools

To build the rust-tools (`make rust-tools`) one needs:

- rust >= 1.35
- cargo with vendor subcommand (now upstream, included in latest Fedora and RHEL8)

### cargo vendpr

- run `cargo vendor` in the disrectory with sources
- run `tar czf device-mapper-persistent-data-vendor-$VERSION.tar.gz ./vendor`
- copy the file (if version changed) and run the *fedpkg new-sources* command:
    - `fedpkg new-sources v$VERSION.tar.gz device-mapper-persistent-data-vendor-$VERSION.tar.gz`

## TODO/NOTES

Some of the dependencies may be already packaged by Fedora. Can we instruct *cargo vendor* to include only those which are not provided by Fedora?

*%cargo_install* installs by defualt in */usr/bin* but the package expects */usr/sbin*. For now I run *make install-rust-tools*.

