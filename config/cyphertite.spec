# $cyphertite$

%define name		cyphertite
%define version		0.3.0
%define release		1

Name: 		%{name}
Summary: 	High-security scalable solution for online backups
Version: 	%{version}
Release: 	%{release}
License: 	ISC
Group: 		System Environment/Libraries
URL:		http://opensource.conformal.com/wiki/cyphertite
Source: 	%{name}-%{version}.tar.gz
Buildroot:	%{_tmppath}/%{name}-%{version}-buildroot
Prefix: 	/usr
Requires:	assl >= 0.10.0, clog >= 0.3.4, exude >= 0.3.0, shrink >= 0.2.1
Requires:	xmlsd >= 0.3.1, libbsd, libevent >= 1.4, sqlite >= 3.6.23

%description
Cyphertite is a high-security scalable solution for online backups.
- Rock Solid: we safeguard your critical data like no other backup company
- Total Privacy: your data is fully sheltered by our encryption process
- Real Security: your data is protected, secure and always available, only to
  you
- Super Efficient: deduplication and realm-wide deduplication before
  transmission
  accelerates back-ups, creating a more time- and cost-efficient work flow
- No Hassle: Cyphertite was built to keep your life simple and easy with an
  intuitive and simple interface
- Supports IPv4 and IPv6 seamlessly

%prep
%setup -q

%build
make

%install
make install DESTDIR=$RPM_BUILD_ROOT LOCALBASE=/usr
rm -rf $RPM_BUILD_ROOT/usr/include/cyphertite
rm -f $RPM_BUILD_ROOT/usr/lib/libctutil.a

%files
%defattr(-,root,root)
%doc /usr/share/man/man?/*
/usr/bin/cyphertite

%changelog
* Tue Jul 26 2011 - davec 0.3.0-1
- Modify wizard to create the configuration path and to run it at more
  expected times
- Add max_mdcache_size to config file to govern that the cache dir doesn't grow
  beyond set value
- Add md_max_differentials to config file to govern when a new level 0 backup
  is run
- Ensure that all metadata parts are downloaded before starting the extract
  operation
- Prevent asymmetrical differential backups from running
- Improve some error messages
- Fix a couple of bugs in the differential backup code path
* Tue Jul 03 2011 - davec 0.2.0-1
- Create
