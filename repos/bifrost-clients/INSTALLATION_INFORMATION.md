# Installation Information

This file is delivered with every corresponding client source bundle as GPLv3
Installation Information. It records the information needed to install and
modify the client without relying on a private Bifrost service.

* Android builds use the pinned JDK, Android SDK/NDK and Gradle versions named
  in the signed build-input manifest. The three supported ABI APKs are built
  from the checked-in Gradle project and its verification/lock inputs.
* Windows builds use the pinned .NET SDK and the checked-in WPF, service and
  installer projects. The installer consumes only the verified release plan;
  it does not discover a manifest or core from the current directory.
* The Windows graphical installer accepts an independent directory on any
  local fixed disk. It rejects a bare volume root and foreign/non-empty trees,
  then applies a protected SYSTEM/Administrators ACL to the selected Bifrost
  directory before installing the verified generation. The optional
  single-file offline wrapper only embeds/extracts the signed package and
  forwards the selected path to that same installer; it is not a second trust
  or update path.
* A local build without the release signing ceremony is marked
  `unsigned-local` and is not a production update package. The release gate
  fails closed when the ceremony public artifacts, core source provenance or
  dependency verification inputs are missing.
* The corresponding source offer is the signed `SOURCE-BUNDLE.tar` artifact;
  its canonical manifest and archive SHA-256 are checked before unpacking.
* No installation step requires a private key, a Control/Node checkout, a
  network lookup, or an undisclosed runtime credential. Real Windows SCM/TUN
  and Android device installation are platform gates outside this local bundle
  and are reported PENDING-EXTERNAL.

There are no additional restrictions on copying, modifying or redistributing
the client under GPLv3.
