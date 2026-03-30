package com.jetbrains.signatureverifier.crypt;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;

import java.security.cert.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class CustomPkixBuilderParameters extends PKIXBuilderParameters {
  private final Store<X509CertificateHolder> _intermediateCertsStore;
  private final X509CertSelector _primaryCert;

  public CustomPkixBuilderParameters(
    HashSet<TrustAnchor> rootCertificates,
    Store<X509CertificateHolder> intermediateCertsStore,
    X509CertSelector primaryCert,
    LocalDateTime signValidationTime) throws Exception {

    super(rootCertificates, primaryCert);
    _intermediateCertsStore = intermediateCertsStore;
    _primaryCert = primaryCert;

    if (signValidationTime != null)
      setDate(Utils.ConvertToDate(signValidationTime));

    setRevocationEnabled(false);
    addCertStore(BcExt.ToJavaCertStore(intermediateCertsStore));
    addCertPathChecker(new CustomPkixCertPathChecker());
    setPolicyQualifiersRejected(false);
  }

  /**
   * Prepare CRLs for all certificates.
   *
   * @return true if CRLs successfully added, false if CRLs can not be used (and OCSP is considered)
   */
  public boolean PrepareCrls(CrlProvider crlProvider) throws Exception {
    List<X509CertificateHolder> certs = new ArrayList<>(_intermediateCertsStore.getMatches(null));
    certs.add(BcExt.ToX509CertificateHolder(_primaryCert.getCertificate()));
    certs.removeIf(cert -> BcExt.IsSelfSigned(cert));

    // distinctBy issuer+serialNumber
    Map<String, X509CertificateHolder> seen = new LinkedHashMap<>();
    for (X509CertificateHolder cert : certs) {
      String key = cert.getIssuer().toString() + ":" + cert.getSerialNumber().toString();
      seen.putIfAbsent(key, cert);
    }
    List<X509CertificateHolder> allCerts = new ArrayList<>(seen.values());

    Collection<X509CRLHolder> allCrls = getCrlsForCerts(crlProvider, allCerts);
    if (allCrls == null) return true;

    CollectionStore<X509CRLHolder> crlStore = new CollectionStore<>(allCrls);
    addCertStore(BcExt.ToJavaCrlStore(crlStore));
    setRevocationEnabled(true);
    return false;
  }

  @Override
  public List<PKIXCertPathChecker> getCertPathCheckers() {
    List<PKIXCertPathChecker> list = new ArrayList<>();
    list.add(new CustomPkixCertPathChecker());
    return list;
  }

  private Collection<X509CRLHolder> getCrlsForCerts(
    CrlProvider crlProvider,
    Collection<X509CertificateHolder> allCerts) throws Exception {

    List<X509CRLHolder> allCrls = new ArrayList<>();
    for (X509CertificateHolder cert : allCerts) {
      Collection<X509CRLHolder> certCrls = crlProvider.GetCrlsAsync(cert);
      List<X509CRLHolder> validCrls = new ArrayList<>();
      for (X509CRLHolder crl : certCrls) {
        if (crl.getThisUpdate().before(cert.getNotAfter()))
          validCrls.add(crl);
      }
      if (validCrls.isEmpty())
        return null;
      allCrls.addAll(validCrls);
    }

    // distinctBy issuer
    Map<String, X509CRLHolder> seen = new LinkedHashMap<>();
    for (X509CRLHolder crl : allCrls) {
      seen.putIfAbsent(crl.getIssuer().toString(), crl);
    }
    return seen.values();
  }
}
