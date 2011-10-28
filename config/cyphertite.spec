
%define name		cyphertite
%define version		0.4.7
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
Requires:	assl >= 0.11.0, clog >= 0.4.0, exude >= 0.5.0, shrink >= 0.3.0
Requires:	xmlsd >= 0.6.0, libbsd, libevent >= 1.4, sqlite >= 3.6.23

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
/usr/bin/ct
/usr/bin/ctctl
/usr/bin/cyphertitectl

%changelog
* Thu Oct 06 2011 - davec 0.4.7-1
- Fix -E flag when used with -0 flag and non-differential backups - FS#169
- Make -C flag work as intended in all modes
- Fix local database initialization - FS#164
- Correct reduction ratio displayed in stats - FS#167
- Add debug print for scheduled files - FS#161
- Other minor cleanup and bug fixes
* Thu Sep 29 2011 - davec 0.4.6-1
- Handle case where none of the specified backup objects exist
- Modify inclusion/exclusion processing to use full paths instead
  of only the filename on Linux
- Properly restore suid bits with and without -p option
- Store basename of backup file in remote mode incremental backups
- Fix error when a symlink exists in the backup prefix
- Add framework for upcoming features
- General improvements and bug fixes
* Tue Sep 20 2011 - drahn 0.4.5-1
- Fix bug where config file specified with -F will not activate properly
- Fix memory leak.
* Tue Sep 20 2011 - drahn 0.4.4-1
- Source code cleanup for CVS -> git migration
- General code cleanup and bug fixes
* Tue Sep 13 2011 - davec 0.4.3-1
- Add logic to better handle differential extracts over an existing file
  system
- Misc code cleanup and bug fixes
* Mon Aug 29 2011 - dhill 0.4.2-1
- New metadata format introduced; shrinks md archives for most users by
  not storing redundant path names for each file
- Speed up operations that do not need crypto secrets by not decrypting
  secrets upon startup
- Switch to xmlsd_generate in libxmlsd instead of using printf XML
  generation
- Minor fixes and improvements
* Wed Aug 18 2011 - davec 0.4.1-1
- Reimplement logic to prevent cyphertite from exiting immediately when
  a file or directory can't be written during extract
- Fix various memory leaks
- Other misc cleanup and minor bug fixes
* Mon Aug 15 2011 - davec 0.4.0-1
- Improve return messages to cyphertite from the backend
- Add ctctl tool to change local crypto password
- Fixed a metadata bug that made mixed endian architectures fail
- Extract creates temporary files and then renames them instead of
  extracting directly into the original filename
- Make cyphertite less verbose when server idle disconnects
- Add support for include and exclude patterns for archive mode
- Validate metadata file before commencing extract operation
- Log file and directory creation errors and continue rather than
  exiting immediately
- Fix a bug in the configuration file creation wizard where the
  wrong pointer was checked for a memory allocation
- Fix a bug where crypto secrets could not be copied between little and
  big endian machines and vice versa
* Wed Aug 03 2011 - davec 0.3.2-1
- Dramatically decrease memory footprint of cyphertite
- Add XML definitions for expanded metada list mode
- Print out the filesize and mtime from the server prettily in md list mode
- Permit differential backups of absolute paths to come from different working
  directories
- Improve error reporting
- Other misc bug fixes
* Wed Jul 27 2011 - davec 0.3.1-1
- Man page updates
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
