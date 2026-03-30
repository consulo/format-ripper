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
  private final InputStream signRootCertStore;
  private final InputStream timestampRootCertStore;

  public final boolean buildChain;
  public final boolean withRevocationCheck;
  public final Duration ocspResponseTimeout;
  public final SignatureValidationTimeMode signValidationTimeMode;
  public LocalDateTime signatureValidationTime;

  private boolean rootCertificatesLoaded = false;
  private HashSet<TrustAnchor> rootCertificates = null;

  public SignatureVerificationParams(InputStream signRootCertStore,
                                     InputStream timestampRootCertStore,
                                     boolean buildChain,
                                     boolean withRevocationCheck,
                                     Duration ocspResponseTimeout,
                                     SignatureValidationTimeMode signatureValidationTimeMode,
                                     LocalDateTime signatureValidationTime) {
    this.signRootCertStore = signRootCertStore;
    this.timestampRootCertStore = timestampRootCertStore;
    this.buildChain = buildChain;
    this.withRevocationCheck = withRevocationCheck;
    this.ocspResponseTimeout = ocspResponseTimeout != null ? ocspResponseTimeout : Duration.ofSeconds(5);
    this.signValidationTimeMode = signatureValidationTimeMode != null
      ? signatureValidationTimeMode
      : SignatureValidationTimeMode.Timestamp;

    if (this.signValidationTimeMode == SignatureValidationTimeMode.SignValidationTime
      && signatureValidationTime == null)
      throw new IllegalArgumentException("signatureValidationTime is empty");

    this.signatureValidationTime = signatureValidationTime;
  }

  public SignatureVerificationParams(InputStream signRootCertStore,
                                     InputStream timestampRootCertStore,
                                     boolean buildChain,
                                     boolean withRevocationCheck) {
    this(signRootCertStore, timestampRootCertStore, buildChain, withRevocationCheck,
      Duration.ofSeconds(5), SignatureValidationTimeMode.Timestamp, null);
  }

  public void setSignValidationTime(LocalDateTime signValidationTime) {
    if (signValidationTimeMode != SignatureValidationTimeMode.Timestamp)
      throw new IllegalStateException("Invalid signValidationTimeMode");
    if (signatureValidationTime != null)
      throw new IllegalStateException("signatureValidationTime already set");
    signatureValidationTime = signValidationTime;
  }

  public HashSet<TrustAnchor> getRootCertificates() {
    if (!rootCertificatesLoaded) {
      rootCertificates = readRootCertificates();
      rootCertificatesLoaded = true;
    }
    return rootCertificates;
  }

  private HashSet<TrustAnchor> readRootCertificates() {
    if (signRootCertStore == null && timestampRootCertStore == null) return null;

    HashSet<TrustAnchor> rootCerts = new HashSet<>();
    try {
      if (signRootCertStore != null) addCerts(signRootCertStore, rootCerts);
      if (timestampRootCertStore != null) addCerts(timestampRootCertStore, rootCerts);
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
    return "buildChain: " + buildChain
      + ", withRevocationCheck: " + withRevocationCheck
      + ", ocspResponseTimeout: " + ocspResponseTimeout
      + ", signValidationTimeMode: " + signValidationTimeMode
      + ", signatureValidationTime: " + signatureValidationTime;
  }
}
