package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.Resources;
import com.jetbrains.signatureverifier.crypt.SignatureVerificationParams;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class DefaultRootsTest {
  @Test
  void test() throws Exception {
    Object[][] expectedCertificates = {
      {"Apple Root CA",                             new BigInteger("02", 16)},
      {"Certum Trusted Network CA",                 new BigInteger("0444c0", 16)},
      {"DigiCert Trusted Root G4",                  new BigInteger("059b1b579e8e2132e23907bda777755c", 16)},
      {"Entrust Root Certification Authority - G2", new BigInteger("4a538c28", 16)},
      {"Go Daddy Root Certificate Authority - G2",  new BigInteger("00", 16)},
      {"Microsoft Root Certificate Authority",      new BigInteger("79ad16a14aa0a5ad4c7358f407132e65", 16)},
      {"Microsoft Root Certificate Authority 2010", new BigInteger("28cc3a25bfba44ac449a9b586b4339aa", 16)},
      {"Microsoft Root Certificate Authority 2011", new BigInteger("3f8bc8b5fc9fb29643b569d66c42e144", 16)},
      {"USERTrust RSA Certification Authority",     new BigInteger("01fd6d30fca3ca51a81bbc640e35032d", 16)},
    };

    Pattern cnPattern = Pattern.compile("CN=(?<CN>[^,]*)");
    SignatureVerificationParams params = new SignatureVerificationParams(
      Resources.GetDefaultRoots(), null, true, false
    );

    List<AbstractMap.SimpleImmutableEntry<String, BigInteger>> certificates = new ArrayList<>();
    for (TrustAnchor anchor : params.getRootCertificates()) {
      X509Certificate cert = anchor.getTrustedCert();
      Matcher matcher = cnPattern.matcher(cert.getIssuerDN().getName());
      String name = matcher.find() ? matcher.group("CN") : null;
      certificates.add(new AbstractMap.SimpleImmutableEntry<>(name, cert.getSerialNumber()));
    }
    certificates.sort(Comparator.comparing(AbstractMap.SimpleImmutableEntry::getKey));

    Assertions.assertEquals(expectedCertificates.length, certificates.size());
    for (int n = 0; n < certificates.size(); n++) {
      Assertions.assertEquals(expectedCertificates[n][0], certificates.get(n).getKey());
      Assertions.assertEquals(expectedCertificates[n][1], certificates.get(n).getValue());
    }
  }
}
