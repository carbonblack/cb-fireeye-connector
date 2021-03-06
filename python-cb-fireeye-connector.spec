%define name python-cb-fireeye-connector
%define version 1.1
%define unmangled_version 1.1
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}

Summary: Carbon Black FireEye Connector
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Bit9
Url: http://www.bit9.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{unmangled_version}

%build
pyinstaller cb-fireeye-connector.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)

%config(noreplace)
/etc/cb/integrations/fireeye/connector.conf


%posttrans
chkconfig --add cb-fireeye-connector
chkconfig --level 345 cb-fireeye-connector on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-fireeye-connector start


%preun
/etc/init.d/cb-fireeye-connector stop

# only delete the chkconfig entry when we uninstall for the last time,
# not on upgrades
if [ "X$1" = "X0" ]
then
    chkconfig --del cb-fireeye-connector
fi
