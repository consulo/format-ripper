package com.jetbrains.signatureverifier.crypt;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;

public class SignatureVerificationParams {
  private final InputStream _signRootCertStore;
  private final InputStream _timestampRootCertStore;

  public final boolean BuildChain;
  public final boolean WithRevocationCheck;
  public final Duration OcspResponseTimeout;
  public final SignatureValidationTimeMode SignValidationTimeMode;
  public LocalDateTime SignatureValidationTime;

  private boolean _rootCertificatesLoaded = false;
  private HashSet<TrustAnchor> _rootCertificates = null;

  public SignatureVerificationParams(InputStream signRootCertStore,
                                     InputStream timestampRootCertStore,
                                     boolean buildChain,
                                     boolean withRevocationCheck,
                                     Duration ocspResponseTimeout,
                                     SignatureValidationTimeMode signatureValidationTimeMode,
                                     LocalDateTime signatureValidationTime) {
    _signRootCertStore = signRootCertStore;
    _timestampRootCertStore = timestampRootCertStore;
    BuildChain = buildChain;
    WithRevocationCheck = withRevocationCheck;
    OcspResponseTimeout = ocspResponseTimeout != null ? ocspResponseTimeout : Duration.ofSeconds(5);
    SignValidationTimeMode = signatureValidationTimeMode != null
      ? signatureValidationTimeMode
      : SignatureValidationTimeMode.Timestamp;

    if (SignValidationTimeMode == SignatureValidationTimeMode.SignValidationTime
      && signatureValidationTime == null)
      throw new IllegalArgumentException("signatureValidationTime is empty");

    SignatureValidationTime = signatureValidationTime;
  }

  public SignatureVerificationParams(InputStream signRootCertStore,
                                     InputStream timestampRootCertStore,
                                     boolean buildChain,
                                     boolean withRevocationCheck) {
    this(signRootCertStore, timestampRootCertStore, buildChain, withRevocationCheck,
      Duration.ofSeconds(5), SignatureValidationTimeMode.Timestamp, null);
  }

  public void SetSignValidationTime(LocalDateTime signValidationTime) {
    if (SignValidationTimeMode != SignatureValidationTimeMode.Timestamp)
      throw new IllegalStateException("Invalid SignValidationTimeMode");
    if (SignatureValidationTime != null)
      throw new IllegalStateException("SignatureValidationTime already set");
    SignatureValidationTime = signValidationTime;
  }

  public HashSet<TrustAnchor> getRootCertificates() {
    if (!_rootCertificatesLoaded) {
      _rootCertificates = readRootCertificates();
      _rootCertificatesLoaded = true;
    }
    return _rootCertificates;
  }

  private HashSet<TrustAnchor> readRootCertificates() {
    if (_signRootCertStore == null && _timestampRootCertStore == null) return null;

    HashSet<TrustAnchor> rootCerts = new HashSet<>();
    try {
      if (_signRootCertStore != null) addCerts(_signRootCertStore, rootCerts);
      if (_timestampRootCertStore != null) addCerts(_timestampRootCertStore, rootCerts);
    } catch (Exception e) {
      throw new RuntimeException("Failed to read root certificates", e);
    }
    return rootCerts;
  }

  private void addCerts(InputStream storeStream, HashSet<TrustAnchor> rootCerts) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Collection<? extends java.security.cert.Certificate> certs = cf.generateCertificates(storeStream);
    for (java.security.cert.Certificate cert : certs) {
      rootCerts.add(new TrustAnchor((X509Certificate) cert, null));
    }
  }

  @Override
  public String toString() {
    return "BuildChain: " + BuildChain
      + ", WithRevocationCheck: " + WithRevocationCheck
      + ", OcspResponseTimeout: " + OcspResponseTimeout
      + ", SignValidationTimeMode: " + SignValidationTimeMode
      + ", SignatureValidationTime: " + SignatureValidationTime;
  }
}
