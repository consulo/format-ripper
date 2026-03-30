package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.crypt.Utils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import java.math.BigInteger;
import java.security.*;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.*;

public class FakePki {
  private static final ASN1ObjectIdentifier RSA_ENCRYPTION = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1");
  private static final ASN1ObjectIdentifier SHA1_WITH_RSA_SIGNATURE = new ASN1ObjectIdentifier("1.2.840.113549.1.1.5");
  private static final int PUBLIC_KEY_LENGTH = 1024;

  public static FakePki createRoot(String name, Date utcValidFrom, Date utcValidTo) {
    if (!utcValidFrom.before(utcValidTo))
      throw new IllegalArgumentException("utcValidTo must be greater than utcValidFrom");
    return new FakePki(name, utcValidFrom, utcValidTo);
  }

  private static KeyPair getNewPair() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(PUBLIC_KEY_LENGTH, SecureRandom.getInstance("SHA1PRNG"));
    return keyGen.generateKeyPair();
  }

  private final KeyPair keyPair;
  private final AlgorithmIdentifier signatureAlg;
  private X509CertificateHolder certificate;
  private X509CRLHolder crl;
  private final List<X509CertificateHolder> certificates = new ArrayList<>();
  private final Map<BigInteger, Date> RevokedCertificates = new LinkedHashMap<>();

  public X509CertificateHolder getCertificate() { return certificate; }

  public X509CRLHolder getCrl() { return crl; }
  public void setCrl(X509CRLHolder crl) { this.crl = crl; }

  public Collection<X509CertificateHolder> getIssuedCertificates() { return certificates; }

  private FakePki(String name, Date validFrom, Date validTo) {
    try {
      keyPair = getNewPair();
      signatureAlg = new AlgorithmIdentifier(SHA1_WITH_RSA_SIGNATURE);
      X500Name subject = new X500Name("CN=" + name);
      certificate = enroll(subject, keyPair, name, validFrom, validTo, 0L, false, false);
      crl = createCrl();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public AbstractMap.SimpleImmutableEntry<KeyPair, X509CertificateHolder> Enroll(
    String name, Date validFrom, Date validTo, boolean codeSign) throws Exception {
    KeyPair keyPair = getNewPair();
    X509CertificateHolder certificate = enroll(
      getCertificate().getSubject(), keyPair, name, validFrom, validTo,
      (long) (certificates.size() + 1), true, codeSign
    );
    certificates.add(certificate);
    return new AbstractMap.SimpleImmutableEntry<>(keyPair, certificate);
  }

  public void revoke(X509CertificateHolder certificate, boolean renewCrl) {
    if (isIssued(certificate)) {
      RevokedCertificates.put(certificate.getSerialNumber(), Utils.convertToDate(LocalDateTime.now()));
      if (renewCrl) {
        try { crl = createCrl(); } catch (Exception e) { throw new RuntimeException(e); }
      }
    }
  }

  public void updateCrl() throws Exception {
    crl = createCrl();
  }

  private boolean isIssued(X509CertificateHolder certificate) {
    return certificate.getIssuer().equals(getCertificate().getSubject());
  }

  private X509CertificateHolder enroll(X500Name issuerDN, KeyPair keyPair, String subjectName,
                                        Date validFrom, Date validTo, long sn,
                                        boolean addCrlDp, boolean codeSign) throws Exception {
    ASN1Encodable version   = new DERTaggedObject(true, 0, new ASN1Integer(2));
    ASN1Integer serialNumber = new ASN1Integer(sn);
    Time startDate = new Time(validFrom);
    Time endDate   = new Time(validTo);
    DERSequence dates = new DERSequence(new ASN1Encodable[]{startDate, endDate});
    X500Name subject = new X500Name("CN=" + subjectName);
    AlgorithmIdentifier alg = new AlgorithmIdentifier(RSA_ENCRYPTION);
    java.security.interfaces.RSAPublicKey rsaKeyParameters = (java.security.interfaces.RSAPublicKey) keyPair.getPublic();
    byte[] keyData = new RSAPublicKey(rsaKeyParameters.getModulus(), rsaKeyParameters.getPublicExponent()).getEncoded();
    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(alg, keyData);

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.addAll(new ASN1Encodable[]{version, serialNumber, signatureAlg, issuerDN, dates, subject, subjectPublicKeyInfo});

    List<Extension> extValues = new ArrayList<>();
    if (addCrlDp) {
      GeneralNames names = new GeneralNames(new GeneralName(
        GeneralName.uniformResourceIdentifier, new DERIA5String("http://fakepki/crl")));
      CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[]{
        new DistributionPoint(new DistributionPointName(DistributionPointName.FULL_NAME, names), null, null)
      });
      extValues.add(Extension.create(Extension.cRLDistributionPoints, false, crlDistPoint));
    }
    if (codeSign) {
      extValues.add(Extension.create(Extension.extendedKeyUsage, false,
        new DERSequence(KeyPurposeId.id_kp_codeSigning)));
    }
    if (!extValues.isEmpty()) {
      Extensions ext = new Extensions(extValues.toArray(new Extension[0]));
      addOptionalTagged(vec, true, 3, ext);
    }

    DERSequence seq = derSequence(vec);
    TBSCertificate tbs = TBSCertificate.getInstance(seq);
    byte[] tbsData = tbs.getEncoded();
    byte[] sig = sign(tbsData, keyPair);
    org.bouncycastle.asn1.x509.Certificate cs = org.bouncycastle.asn1.x509.Certificate.getInstance(
      derSequence(tbs, signatureAlg, new DERBitString(sig))
    );
    return new X509CertificateHolder(cs);
  }

  private X509CRLHolder createCrl() throws Exception {
    ASN1Integer version = new ASN1Integer(1);
    X500Name issuer = getCertificate().getSubject();
    LocalDateTime now = LocalDateTime.now(Clock.systemUTC()).plusMinutes(1);
    Time thisUpdate = new Time(Utils.convertToDate(now));
    Time nextUpdate = new Time(Utils.convertToDate(now.plusDays(5)));
    DERSequence revokedCertificates = getRevokedCertificates();
    DERSequence seq = derSequence(version, signatureAlg, issuer, thisUpdate, nextUpdate, revokedCertificates);
    TBSCertList tbs = TBSCertList.getInstance(seq);
    byte[] tbsData = tbs.getEncoded();
    byte[] sig = sign(tbsData, keyPair);
    CertificateList certList = CertificateList.getInstance(derSequence(tbs, signatureAlg, new DERBitString(sig)));
    return new X509CRLHolder(certList);
  }

  private DERSequence getRevokedCertificates() {
    ASN1EncodableVector vec = new ASN1EncodableVector();
    for (Map.Entry<BigInteger, Date> entry : RevokedCertificates.entrySet()) {
      vec.add(getRevokedCertificate(entry.getKey(), entry.getValue()));
    }
    return new DERSequence(vec);
  }

  private static DERSequence getRevokedCertificate(BigInteger serialNumber, Date revocationTime) {
    return new DERSequence(new ASN1Encodable[]{new ASN1Integer(serialNumber), new Time(revocationTime)});
  }

  private byte[] sign(byte[] data, KeyPair key) throws Exception {
    Signature signature = Signature.getInstance(signatureAlg.getAlgorithm().getId());
    signature.initSign(key.getPrivate());
    signature.update(data);
    return signature.sign();
  }

  private static void addOptionalTagged(ASN1EncodableVector vec, boolean isExplicit, int tagNo, ASN1Encodable obj) {
    if (obj != null) {
      vec.add(new DERTaggedObject(isExplicit, tagNo, obj));
    }
  }

  private static DERSequence derSequence(ASN1Encodable... items) {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.addAll(items);
    return new DERSequence(v);
  }

  private static DERSequence derSequence(ASN1EncodableVector vec) {
    return new DERSequence(vec);
  }
}
