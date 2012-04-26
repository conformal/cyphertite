%define name		cyphertite
%define version		1.2.1
%define release		1

%define libeventpkg	libevent
%define is_fc14		%(test "%{?dist}" = ".fc14" && echo 1 || echo 0)
%if %{is_fc14}
%define libeventpkg	libevent2
%endif

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
Requires:	assl >= 1.0.0, clog >= 0.4.0, exude >= 0.6.0, shrink >= 0.3.0
Requires:	xmlsd >= 0.7.0, libbsd, %{libeventpkg} >= 2.0, sqlite >= 3.6.23
Requires:	libedit >= 3.0, libcurl >= 7.11

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
/usr/bin/ctfb
/usr/bin/cyphertitefb

%changelog
* Thu Apr 26 2012 - davec 1.2.1-1
- Fix a bug in automatic certificate retrieval
- Improve handling of path splitting
- Correct some package dependencies
- Other minor code cleanup
* Tue Apr 24 2012 - drahn 1.2.0-1
- Automatically retrieve certificate bundle during configuration
  file generation
- Simplify default configuration file generation
- Add an expert mode to provide the previous configurability
- Configuration file generation now creates a temporary file and
  renames it instead of writing directly
- Move to libevent2
- Cleanup thread handling and use updated thread safe libraries
- Compensate for lack of openat on OpenBSD prior to 5.0
- Other minor cleanup and bug fixes
* Wed Mar 28 2012 - drahn 1.1.1-1
- Add pthreads support to provide a performance boost over previous
  releases of cyphertite
- Fix extract error when extracting to another directory ie '-C'
- Fix cull path problem where files were downloaded incorrectly
- Update Copyrights for 2012
- Packaging fixes for FreeBSD
* Fri Mar 23 2012 - drahn 1.1.0-1
- Fix major error in cull processing
- Implement a major security enhancement on most systems by using
  openat(2) to securely walk directory trees instead of opening
  paths which could get renamed out from under the application
- Cyphertite configuration file generation is now performed with
  'cyphertitectl config generate'
- Crypto secrets file generation is now done during configuration file
  generation, or explicitly with 'cyphertitectl secrets generate', as
  opposed  to automatically generating it
- Add ctctl secrets upload/download to store a user's secrets file 
  on the server
- Change the cyphertitectl command to change the secrets password to
  'ctctl secrets passwd'
- Allow specific debug levels to be disabled, eg '-Dall,-exude'
- Fix error in cyphertite file browser related to rooted backups (-cP)
- Other minor cleanup and bug fixes
* Tue Mar 13 2012 - drahn 1.0.2-1
- Consistently use ctfile instead of md (metadata) file
- Documentation cleanup
- Other internal cleanup and bug fixes
* Mon Feb 27 2012 - davec 1.0.1-1
- Normalize user names to match web accounts
- Add support for latest version of libevent
- Improve and cleanup man pages
- Include cyphertitectl (ctctl) man page in packages
- Implement build versioning on Linux to match support on BSD
- Allow manpages to be accessed with their short names on Linux
- Improve usage clarity
- Improve error reporting when loading file certificates
- Fixed an issue regarding listing contents of an incremental backup
- Other minor bug fixes, misc code cleanup, and improvements
* Mon Feb 13 2012 - drahn 1.0.0-1
- Handle files truncated or growing during backup, best effort will be
  made to archive the files
- Report useful error message when a user runs out of space on a limited
  space account
- Add a method to implment backups instead of archives,
  for more information see the manpage 'BACKUP vs ARCHIVE' section
- Change internal encoding of filenames as ct archives are backed up on
  server to  provide better internationalization support
- Cyphertite file browser usage changes and operation improvements
- Minor fixes and improvements
* Fri Jan 06 2012 - davec 0.6.1-1
- Improve file browser utility (cyphertitefb)
- Recommend .ct as the extension for metadata archive files
- Implement debug trace filtering with '-D flagname'
- Negotiate local database revision and sync with server
- Other misc code cleanup and improvements
* Fri Dec 02 2011 - davec 0.6.0-1
- Enable UTF-8 support for file names
- Add a new file browser utility (cyphertitefb)
- Implement logic to validate the specified 'ctfile'
- Fix an issue when all specified files are excluded via the -E option
- Correct -P behavior
- Add change log in root directory
- General code cleanup and improvements
* Wed Nov 09 2011 - davec 0.5.0-1
- Fix certain scenarios where extracting incremental backups
  could cause files to be restored to the wrong directory
- Update to use latest version of openssl (1.0.0e)
- Consolidate configuration and operational files into a single
  directory by default
- Other misc code cleanup and improvements
* Fri Oct 28 2011 - davec 0.4.8-1
- Add infrastructure for automatic feature negotiation
- Fix metadata tag list output to allow copy/pasting with special chars
- Update to use latest versions of several dependency libraries
- Add build versioning
- Improve code portability
- Other minor cleanup and bug fixes
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
