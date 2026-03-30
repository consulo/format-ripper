package com.jetbrains.signatureverifier.crypt;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class BcExt {
  public static String Dump(org.bouncycastle.asn1.ASN1Encodable obj) {
    return ASN1Dump.dumpAsString(obj);
  }

  public static void DumpToConsole(org.bouncycastle.asn1.ASN1Encodable obj) {
    System.out.println(Dump(obj));
  }

  public static String SN(Certificate cert) throws Exception {
    return ConvertToHexString(cert.getSerialNumber().getValue().toByteArray()).toUpperCase();
  }

  public static String Thumbprint(Certificate cert) throws Exception {
    return ConvertToHexString(MessageDigest.getInstance("SHA1").digest(cert.getEncoded()));
  }

  public static String Thumbprint(X509CertificateHolder cert) throws Exception {
    return ConvertToHexString(MessageDigest.getInstance("SHA1").digest(cert.getEncoded()));
  }

  public static String ConvertToHexString(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  public static String GetOcspUrl(Certificate cert) {
    return getOcspUrl(cert.getTBSCertificate().getExtensions());
  }

  public static String GetOcspUrl(X509CertificateHolder cert) {
    return getOcspUrl(cert.getExtensions());
  }

  private static String getOcspUrl(Extensions extensions) {
    if (extensions == null) return null;
    AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.fromExtensions(extensions);
    if (authorityInformationAccess == null) return null;
    for (AccessDescription desc : authorityInformationAccess.getAccessDescriptions()) {
      if (desc.getAccessMethod().equals(OIDs.OCSP)) {
        return ((DERIA5String) desc.getAccessLocation().getName()).getString();
      }
    }
    return null;
  }

  public static List<String> GetCrlDistributionUrls(X509CertificateHolder cert) throws Exception {
    List<String> res = new ArrayList<>();
    CRLDistPoint crldp = CRLDistPoint.fromExtensions(cert.getExtensions());
    if (crldp != null) {
      DistributionPoint[] dps;
      try {
        dps = crldp.getDistributionPoints();
      } catch (Exception e) {
        throw new Exception("Distribution points could not be read.", e);
      }
      for (DistributionPoint dp : dps) {
        DistributionPointName dpn = dp.getDistributionPoint();
        if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
          GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
          for (GeneralName genName : genNames) {
            if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
              String location = org.bouncycastle.asn1.ASN1IA5String.getInstance(genName.getName()).getString();
              res.add(location);
            }
          }
        }
      }
    }
    return res;
  }

  public static boolean HasCrlDistributionPoints(Certificate cert) {
    CRLDistPoint crldp = CRLDistPoint.fromExtensions(cert.getTBSCertificate().getExtensions());
    return crldp != null;
  }

  public static boolean IsSelfSigned(Certificate cert) {
    return cert.getIssuer().equals(cert.getSubject());
  }

  public static boolean IsSelfSigned(X509CertificateHolder cert) {
    return cert.getIssuer().equals(cert.getSubject());
  }

  public static boolean CanSignOcspResponses(Certificate cert) {
    Collection<String> eku = GetExtendedKeyUsage(cert);
    return eku != null && eku.contains(KeyPurposeId.id_kp_OCSPSigning.getId());
  }

  public static boolean CanSignOcspResponses(X509CertificateHolder cert) {
    Collection<String> eku = GetExtendedKeyUsage(cert);
    return eku != null && eku.contains(KeyPurposeId.id_kp_OCSPSigning.getId());
  }

  public static Collection<String> GetExtendedKeyUsage(X509CertificateHolder cert) {
    return getExtendedKeyUsage(cert.getExtensions());
  }

  public static Collection<String> GetExtendedKeyUsage(Certificate cert) {
    return getExtendedKeyUsage(cert.getTBSCertificate().getExtensions());
  }

  private static Collection<String> getExtendedKeyUsage(Extensions extensions) {
    if (extensions == null) return null;
    org.bouncycastle.asn1.ASN1Encodable str = extensions.getExtensionParsedValue(new ASN1ObjectIdentifier("2.5.29.37"));
    if (str == null) return null;
    try {
      ASN1Sequence seq = ASN1Sequence.getInstance(fromExtensionValue(str));
      List<String> list = new ArrayList<>();
      for (org.bouncycastle.asn1.ASN1Encodable enc : seq) {
        list.add(((ASN1ObjectIdentifier) enc).getId());
      }
      return list;
    } catch (Exception e) {
      throw new RuntimeException("error processing extended key usage extension", e);
    }
  }

  private static ASN1Primitive fromExtensionValue(org.bouncycastle.asn1.ASN1Encodable enc) throws Exception {
    return ASN1Primitive.fromByteArray(enc.toASN1Primitive().getEncoded());
  }

  public static String GetAuthorityKeyIdentifier(Certificate cert) throws Exception {
    AuthorityKeyIdentifier ki = AuthorityKeyIdentifier.fromExtensions(cert.getTBSCertificate().getExtensions());
    if (ki == null || ki.getKeyIdentifier() == null) return null;
    return ConvertToHexString(ki.getKeyIdentifier());
  }

  public static String GetAuthorityKeyIdentifier(X509CertificateHolder cert) throws Exception {
    AuthorityKeyIdentifier ki = AuthorityKeyIdentifier.fromExtensions(cert.getExtensions());
    if (ki == null || ki.getKeyIdentifier() == null) return null;
    return ConvertToHexString(ki.getKeyIdentifier());
  }

  public static String GetSubjectKeyIdentifier(Certificate cert) throws Exception {
    SubjectKeyIdentifier ki = SubjectKeyIdentifier.fromExtensions(cert.getTBSCertificate().getExtensions());
    if (ki == null || ki.getKeyIdentifier() == null) return null;
    return ConvertToHexString(ki.getKeyIdentifier());
  }

  public static byte[] GetSubjectKeyIdentifierRaw(Certificate cert) {
    SubjectKeyIdentifier ki = SubjectKeyIdentifier.fromExtensions(cert.getTBSCertificate().getExtensions());
    return ki != null ? ki.getKeyIdentifier() : null;
  }

  public static byte[] GetSubjectKeyIdentifierRaw(X509CertificateHolder cert) {
    SubjectKeyIdentifier ki = SubjectKeyIdentifier.fromExtensions(cert.getExtensions());
    return ki != null ? ki.getKeyIdentifier() : null;
  }

  public static String FormatId(Certificate cert) throws Exception {
    return "Issuer=" + cert.getIssuer() + "; SN=" + SN(cert);
  }

  public static String FormatId(X509CertificateHolder cert) throws Exception {
    Certificate asn1Cert = cert.toASN1Structure();
    return "Issuer=" + asn1Cert.getIssuer() + "; SN=" + SN(asn1Cert);
  }

  public static org.bouncycastle.asn1.ASN1Encodable GetFirstAttributeValue(AttributeTable table, ASN1ObjectIdentifier oid) {
    org.bouncycastle.asn1.cms.Attribute attr = table.get(oid);
    if (attr != null && attr.getAttrValues().size() > 0) {
      return attr.getAttributeValues()[0];
    }
    return null;
  }

  public static X509Certificate ToJavaX509Certificate(X509CertificateHolder cert) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    try (ByteArrayInputStream bis = new ByteArrayInputStream(cert.getEncoded())) {
      return (X509Certificate) cf.generateCertificate(bis);
    }
  }

  public static X509CRL ToJavaX509Crl(X509CRLHolder crl) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    try (ByteArrayInputStream bis = new ByteArrayInputStream(crl.getEncoded())) {
      return (X509CRL) cf.generateCRL(bis);
    }
  }

  public static CertStore ToJavaCertStore(Store<X509CertificateHolder> store) throws Exception {
    List<X509Certificate> certs = new ArrayList<>();
    for (X509CertificateHolder holder : store.getMatches(null)) {
      certs.add(ToJavaX509Certificate(holder));
    }
    CollectionCertStoreParameters params = new CollectionCertStoreParameters(certs);
    return CertStore.getInstance("Collection", params);
  }

  public static CertStore ToJavaCrlStore(Store<X509CRLHolder> store) throws Exception {
    List<X509CRL> crls = new ArrayList<>();
    for (X509CRLHolder holder : store.getMatches(null)) {
      crls.add(ToJavaX509Crl(holder));
    }
    CollectionCertStoreParameters params = new CollectionCertStoreParameters(crls);
    return CertStore.getInstance("Collection", params);
  }

  public static X509CertificateHolder ToX509CertificateHolder(java.security.cert.Certificate cert) throws Exception {
    return new X509CertificateHolder(cert.getEncoded());
  }
}
