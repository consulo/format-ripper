package com.jetbrains.signatureverifier.crypt;

import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;
import java.util.HashSet;
import java.util.Set;

public class CustomPkixCertPathChecker extends PKIXCertPathChecker {
  @Override
  public void init(boolean forward) {
  }

  @Override
  public boolean isForwardCheckingSupported() {
    return false;
  }

  @Override
  public Set<String> getSupportedExtensions() {
    Set<String> set = new HashSet<>();
    set.add(OIDs.APPLE_CERTIFICATE_EXTENSION_CODE_SIGNING.getId());
    set.add(OIDs.APPLE_CERTIFICATE_EXTENSION_KEXT_SIGNING.getId());
    return set;
  }

  @Override
  public void check(Certificate cert, java.util.Collection<String> unresolvedCritExts) {
    unresolvedCritExts.remove(OIDs.EXTENDED_KEY_USAGE.getId());
    unresolvedCritExts.remove(OIDs.APPLE_CERTIFICATE_EXTENSION_CODE_SIGNING.getId());
    unresolvedCritExts.remove(OIDs.APPLE_CERTIFICATE_EXTENSION_KEXT_SIGNING.getId());
  }
}
