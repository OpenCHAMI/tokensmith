# SPDX-FileCopyrightText: 2026 OpenCHAMI Contributors
# SPDX-License-Identifier: MIT
#
# See `make rpm-build` and docs/RPM_PACKAGING.md for the tag-to-version
# mapping and how the packaged quadlet's image tag is pinned to it.

Name:           tokensmith-quadlet
Version:        %{version}
Release:        %{rel}%{?dist}
Summary:        OpenCHAMI tokensmith Quadlet units

License:        MIT
URL:            https://github.com/OpenCHAMI/tokensmith
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

Requires(post,preun,postun):  systemd
Requires:                     podman >= 5.0.0

%description
Podman Quadlet unit files (container + volume) for running tokensmith
as part of an OpenCHAMI deployment.

%prep
%setup -q

%install
install -d %{buildroot}/etc/openchami/configs
install -d %{buildroot}/usr/share/containers/systemd

grep -q '@IMAGE_TAG@' tokensmith.container
sed "s|@IMAGE_TAG@|v%{version}|" tokensmith.container \
    > %{buildroot}/usr/share/containers/systemd/tokensmith.container
chmod 644 %{buildroot}/usr/share/containers/systemd/tokensmith.container
install -d %{buildroot}/usr/share/containers/systemd/tokensmith.container.d
install -m 644 tokensmith.container.d/10-defaults.conf \
    %{buildroot}/usr/share/containers/systemd/tokensmith.container.d/

install -m 644 tokensmith-data.volume \
    %{buildroot}/usr/share/containers/systemd/tokensmith-data.volume

install -m 644 tokensmith.json.license \
    %{buildroot}/etc/openchami/configs/tokensmith.json.license

install -m 644 tokensmith.json \
    %{buildroot}/etc/openchami/configs/tokensmith.json

%files
%license LICENSES/MIT.txt
%dir /etc/openchami
%dir /etc/openchami/configs
%config(noreplace) /etc/openchami/configs/tokensmith.json
/etc/openchami/configs/tokensmith.json.license
/usr/share/containers/systemd/tokensmith.container
/usr/share/containers/systemd/tokensmith.container.d
/usr/share/containers/systemd/tokensmith.container.d/10-defaults.conf
/usr/share/containers/systemd/tokensmith-data.volume

%post
# reload systemd so the new Quadlet-generated unit is seen
systemctl daemon-reload || :
if [ $1 -ge 2 ]; then
    systemctl try-restart tokensmith.service || :
fi

%preun
if [ $1 -eq 0 ]; then
    systemctl stop tokensmith.service >/dev/null 2>&1 || :
fi

%postun
# reload systemd so the removed unit is dropped
systemctl daemon-reload || :
